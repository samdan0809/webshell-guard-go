// Package updater 程序自升级：
// 远端 manifest(版本号+下载地址+sha256) → 版本比对 → 下载校验 → 原地替换 exe → 重启生效。
//
// Windows 上运行中的 exe 不能被覆盖删除，但可以重命名：
// 先把当前 exe 改名为 .old 备份，再把下载好的新 exe 落到原路径，最后退出进程。
// 服务模式退出码 2 触发 SCM 恢复策略用新版本拉起；控制台模式直接拉起新进程后退出。
package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"webshell-guard/internal/config"
	"webshell-guard/internal/version"
)

// ErrRestart 升级替换完成后由 runCore 返回给调用方，触发进程重启（新版本生效）。
var ErrRestart = errors.New("UPDATE_RESTART")

// Manifest 升级清单（JSON）。url 指向新版 exe；sha256 可选（留空跳过哈希校验）。
// 示例: {"version":"v1.0.1","url":"https://host/webshell-guard.exe","sha256":"...","notes":"修复xxx"}
type Manifest struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Notes   string `json:"notes"`
}

// maxDownloadSize 新版 exe 下载大小上限（防异常地址打爆磁盘）。
const maxDownloadSize = 256 << 20

// Updater 自升级器。
type Updater struct {
	cfg        config.UpdateConfig
	checkURL   string
	authHeader string

	mu        sync.Mutex
	latest    Manifest
	hasNew    bool
	lastCheck time.Time
	lastErr   string

	restartCh chan struct{}
	closeOnce sync.Once
}

// New 创建升级器。workDir 预留（当前临时文件放 exe 同目录）。
func New(cfg config.UpdateConfig, workDir string) *Updater {
	checkURL := strings.TrimSpace(cfg.URL)
	authHeader := strings.TrimSpace(cfg.AuthHeader)
	if authHeader == "" && cfg.Token != "" {
		authHeader = "Authorization: Bearer {token}"
	}
	// {token} 占位替换，与 rules_sync 用法一致
	return &Updater{
		cfg:        cfg,
		checkURL:   strings.ReplaceAll(checkURL, "{token}", cfg.Token),
		authHeader: strings.ReplaceAll(authHeader, "{token}", cfg.Token),
		restartCh:  make(chan struct{}),
	}
}

// Enabled 是否已启用（配置开关 + 清单地址都具备）。
func (u *Updater) Enabled() bool { return u.cfg.Enabled && u.checkURL != "" }

// RestartChan 升级替换成功后关闭，通知 runCore 退出重启。
func (u *Updater) RestartChan() <-chan struct{} { return u.restartCh }

// HasNew 最近一次检查是否发现新版本。
func (u *Updater) HasNew() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hasNew
}

// checkClient 清单请求客户端。
func checkClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

// Check 拉取远端升级清单并与当前版本比对，结果缓存到状态里。
func (u *Updater) Check() (*Manifest, error) {
	if u.checkURL == "" {
		return nil, fmt.Errorf("未配置 update.url")
	}
	req, err := http.NewRequest(http.MethodGet, u.checkURL, nil)
	if err != nil {
		u.record(nil, err)
		return nil, err
	}
	if u.authHeader != "" {
		if i := strings.IndexByte(u.authHeader, ':'); i > 0 {
			req.Header.Set(strings.TrimSpace(u.authHeader[:i]), strings.TrimSpace(u.authHeader[i+1:]))
		}
	}
	resp, err := checkClient().Do(req)
	if err != nil {
		u.record(nil, err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("清单地址返回 HTTP %d", resp.StatusCode)
		u.record(nil, err)
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		u.record(nil, err)
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		u.record(nil, fmt.Errorf("清单不是合法 JSON: %v", err))
		return nil, err
	}
	m.Version = strings.TrimPrefix(strings.TrimSpace(m.Version), "v")
	if m.Version == "" {
		err := fmt.Errorf("清单缺少 version 字段")
		u.record(nil, err)
		return nil, err
	}
	err = nil
	if compareVersion(m.Version, version.Version) > 0 {
		// 有新版本：url 必须具备才标记可升级
		if m.URL == "" {
			err = fmt.Errorf("清单缺少 url, 无法下载新版本")
		}
	}
	u.record(&m, err)
	return &m, err
}

// record 更新检查状态（含 last_check/last_error/has_new）。
func (u *Updater) record(m *Manifest, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lastCheck = time.Now()
	if err != nil {
		u.lastErr = err.Error()
		return
	}
	u.lastErr = ""
	if m != nil {
		u.latest = *m
		u.hasNew = m.URL != "" && compareVersion(m.Version, version.Version) > 0
	}
}

// Apply 下载新版本 → 校验 → 原地替换 exe → 关闭 restartCh 触发重启。
func (u *Updater) Apply() error {
	m := u.latest
	if !u.HasNew() {
		if _, err := u.Check(); err != nil {
			return err
		}
		u.mu.Lock()
		m = u.latest
		u.mu.Unlock()
	}
	if !u.HasNew() {
		return fmt.Errorf("当前已是最新版本 (%s)", version.Version)
	}
	return u.applyManifest(m)
}

// applyManifest 下载、校验并替换 exe。
func (u *Updater) applyManifest(m Manifest) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	tmp := exe + ".new"
	if err := downloadFile(m.URL, u.authHeader, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("下载新版本失败: %v", err)
	}
	// SHA256 校验（清单提供了才校验）
	if want := strings.ToLower(strings.TrimSpace(m.SHA256)); want != "" {
		sum, serr := fileSHA256(tmp)
		if serr != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("计算新版本 SHA256 失败: %v", serr)
		}
		if sum != want {
			_ = os.Remove(tmp)
			return fmt.Errorf("SHA256 校验不符(可能被篡改或下载不完整), 已丢弃: got %s want %s", sum, want)
		}
	}
	// 基本 PE 头检查，防止把错误内容(HTML 报错页等)当程序落盘
	if !isPEFile(tmp) {
		_ = os.Remove(tmp)
		return fmt.Errorf("下载内容不是 Windows 可执行文件, 已丢弃")
	}
	// 替换：运行中的 exe 可重命名不可覆盖
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("备份旧程序失败: %v", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Rename(old, exe) // 回滚，保证旧版本还能跑
		_ = os.Remove(tmp)
		return fmt.Errorf("新版本落盘失败(已回滚): %v", err)
	}
	log.Printf("[update] 已替换为新版本 %s (旧版备份: %s)", m.Version, filepath.Base(old))
	u.closeOnce.Do(func() { close(u.restartCh) })
	return nil
}

// Start 常驻定时检查。auto_apply=true 时发现新版本自动替换并触发重启。
func (u *Updater) Start(stop <-chan struct{}) {
	if !u.Enabled() {
		return
	}
	interval := time.Duration(u.cfg.Interval) * time.Second
	if interval < 5*time.Minute {
		interval = 5 * time.Minute // 防误配过短周期频繁打远端
	}
	go func() {
		u.checkOnce(true)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				u.checkOnce(false)
			}
		}
	}()
}

// checkOnce 定时检查一轮；发现新版本记录状态，AutoApply 时自动替换。
func (u *Updater) checkOnce(first bool) {
	m, err := u.Check()
	if err != nil {
		// 首次检查失败打日志；周期检查失败已记录到 lastErr，避免刷屏
		if first {
			log.Printf("[update] 首次检查更新失败(不影响防护, 下个周期重试): %v", err)
		}
		return
	}
	if !u.HasNew() {
		if first {
			log.Printf("[update] 已是最新版本 (%s)", version.Version)
		}
		return
	}
	log.Printf("[update] 发现新版本 %s (当前 %s): %s", m.Version, version.Version, m.Notes)
	if !u.cfg.AutoApply {
		return
	}
	if aerr := u.Apply(); aerr != nil {
		log.Printf("[update] 自动升级失败: %v", aerr)
		return
	}
	log.Printf("[update] 新版本已替换, 程序即将重启生效")
}

// Status 返回面板展示用的升级状态。
func (u *Updater) Status() map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	lastCheck := ""
	if !u.lastCheck.IsZero() {
		lastCheck = u.lastCheck.Format("2006-01-02 15:04:05")
	}
	return map[string]any{
		"enabled":      u.cfg.Enabled,
		"auto_apply":   u.cfg.AutoApply,
		"version":      version.Version,
		"build_date":   version.BuildDate,
		"latest":       u.latest.Version,
		"notes":        u.latest.Notes,
		"has_new":      u.hasNew,
		"last_check":   lastCheck,
		"last_error":   u.lastErr,
		"download_url": u.latest.URL,
	}
}

// TrayCheck 托盘「检查更新」：同步检查并返回给用户看的提示文本。
func (u *Updater) TrayCheck() string {
	if !u.Enabled() {
		return "未启用自动升级(配置 update.enabled=true 与 update.url)"
	}
	m, err := u.Check()
	if err != nil {
		return "检查更新失败: " + err.Error()
	}
	if u.HasNew() {
		return fmt.Sprintf("发现新版本 %s, 可在面板升级或执行 -update 命令", m.Version)
	}
	return fmt.Sprintf("已是最新版本 (%s)", version.String())
}

// ---- 工具函数 ----

// downloadFile 带 256MB 上限与认证头下载到 path。
func downloadFile(url, authHeader, path string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if authHeader != "" {
		if i := strings.IndexByte(authHeader, ':'); i > 0 {
			req.Header.Set(strings.TrimSpace(authHeader[:i]), strings.TrimSpace(authHeader[i+1:]))
		}
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxDownloadSize))
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("下载内容为空")
	}
	return nil
}

// fileSHA256 计算文件 SHA256。
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// isPEFile 检查文件是否以 MZ 开头（Windows PE 可执行文件）。
func isPEFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [2]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return hdr[0] == 'M' && hdr[1] == 'Z'
}

// compareVersion 点分数字版本号比较：a>b 返回 1，相等返回 0，a<b 返回 -1。
// 无法解析的段按 0 处理（如 dev/日期戳），保证 dev 版本总能被正式版本升级。
func compareVersion(a, b string) int {
	as, bs := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = atoiSafe(as[i])
		}
		if i < len(bs) {
			bv = atoiSafe(bs[i])
		}
		if av > bv {
			return 1
		}
		if av < bv {
			return -1
		}
	}
	return 0
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
