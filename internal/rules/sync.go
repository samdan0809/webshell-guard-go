package rules

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"webshell-guard/internal/detector"
)

// repoRulesDir 共享规则仓库中约定存放规则 yaml 的子目录。
const repoRulesDir = "rules"

// Syncer 规则库 Git/远程同步器。
//
// 职责：定时从远端仓库拉取共享规则 → 校验 → 写入本地缓存文件
// (rules_synced.yaml) → 回调通知上层合并注入检测器。
// 拉取失败时沿用上次缓存，不影响防护。
type Syncer struct {
	mu        sync.Mutex
	cfg       RepoConfig
	cachePath string // rules_synced.yaml
	repoDir   string // git 模式的本地克隆目录
	client    *http.Client
	reconf    chan struct{} // Reconfigure 触发 Start 循环重读配置

	synced   []Def // 最近一次成功拉取并校验通过的规则
	lastPull time.Time
	lastErr  string
	pullCnt  int

	// OnUpdate 每次成功拉取(或缓存变化)后回调，上层用 MergedRules 合并注入检测器。
	OnUpdate func()
}

// RepoConfig 同步来源配置。
type RepoConfig struct {
	Enabled    bool     // 是否启用共享规则同步
	Mode       string   // git | raw
	Repo       string   // git: 仓库地址; raw: 文件 URL 或目录前缀(配合 Files)
	Branch     string   // git 模式分支
	Interval   int      // 秒
	Token      string   // raw 模式认证 token
	AuthHeader string   // raw 模式认证头模板，空则 "Authorization: Bearer {token}"；含 {token} 占位符
	Files      []string // raw 模式: 目录前缀下要拉取的文件名列表；为空则 Repo 为单个文件 URL
}

// NewSyncer 创建同步器（不启动）。cachePath 为 rules_synced.yaml 路径。
func NewSyncer(cfg RepoConfig, workDir string) *Syncer {
	return &Syncer{
		cfg:       cfg,
		cachePath: filepath.Join(workDir, "rules_synced.yaml"),
		repoDir:   filepath.Join(workDir, ".rules-repo"),
		client:    &http.Client{Timeout: 30 * time.Second},
		reconf:    make(chan struct{}, 1),
	}
}

// Reconfigure 运行时替换同步配置（面板保存后调用），Start 循环会立即重读。
func (s *Syncer) Reconfigure(cfg RepoConfig) {
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	select {
	case s.reconf <- struct{}{}:
	default:
	}
}

// Status 同步状态（面板展示）。
type Status struct {
	Enabled  bool      `json:"enabled"`
	Mode     string    `json:"mode"`
	Source   string    `json:"source"` // 展示用，token 不回显
	Branch   string    `json:"branch,omitempty"`
	Interval int       `json:"interval_sec"`
	LastPull string    `json:"last_pull"`
	LastErr  string    `json:"last_error"`
	PullCnt  int       `json:"pull_count"`
	RuleCnt  int       `json:"rule_count"`
	CacheAge string    `json:"cache_age"` // 距上次成功拉取
}

// Status 返回当前状态。
func (s *Syncer) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Enabled:  s.cfg.Enabled,
		Mode:     s.cfg.Mode,
		Interval: s.cfg.Interval,
		PullCnt:  s.pullCnt,
		RuleCnt:  len(s.synced),
		LastErr:  s.lastErr,
	}
	src := s.cfg.Repo
	if i := strings.Index(src, "@"); i > 0 && strings.Contains(src, "://") && strings.Contains(src[:i], ":") {
		src = maskURL(src) // 去掉 URL 中内嵌的凭据
	}
	st.Source = src
	if s.cfg.Mode == "git" {
		st.Branch = s.cfg.Branch
	}
	if !s.lastPull.IsZero() {
		st.LastPull = s.lastPull.Format("2006-01-02 15:04:05")
		st.CacheAge = time.Since(s.lastPull).Round(time.Second).String()
	}
	return st
}

func maskURL(u string) string {
	// scheme://user:pass@host/... → scheme://user:***@host/...
	schemeIdx := strings.Index(u, "://")
	at := strings.LastIndex(u, "@")
	if schemeIdx < 0 || at < schemeIdx {
		return u
	}
	cred := u[schemeIdx+3 : at]
	if c := strings.Index(cred, ":"); c >= 0 {
		cred = cred[:c] + ":***"
	} else {
		cred = "***"
	}
	return u[:schemeIdx+3] + cred + u[at:]
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// SyncedDefs 返回缓存中的共享规则。
func (s *Syncer) SyncedDefs() []Def {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Def, len(s.synced))
	copy(out, s.synced)
	return out
}

// DetectorRules 共享规则转检测器规则（未启用时返回空）。
func (s *Syncer) DetectorRules() []*detector.Rule {
	if !s.enabled() {
		return nil
	}
	return ToDetectorRules(s.SyncedDefs())
}

// enabled 是否启用同步。
func (s *Syncer) enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.Enabled
}

// SyncNow 立即执行一次同步（面板手动触发/启动时调用）。未启用时为空操作。
func (s *Syncer) SyncNow() error {
	if !s.enabled() {
		return nil
	}
	changed, err := s.pull()
	s.mu.Lock()
	if err != nil {
		s.lastErr = err.Error()
	} else {
		s.lastErr = ""
		s.lastPull = time.Now()
		s.pullCnt++
	}
	s.mu.Unlock()
	if err == nil && changed && s.OnUpdate != nil {
		s.OnUpdate()
	}
	return err
}

// Start 启动定时同步循环（阻塞，放 goroutine）。
// 每轮循环读取最新 Interval；Reconfigure 会立即打断等待重读配置。
func (s *Syncer) Start(stop <-chan struct{}) {
	for {
		s.mu.Lock()
		interval := s.cfg.Interval
		s.mu.Unlock()
		if interval < 5 {
			interval = 5
		}
		tick := time.NewTicker(time.Duration(interval) * time.Second)
		select {
		case <-tick.C:
			tick.Stop()
			_ = s.SyncNow()
		case <-s.reconf:
			tick.Stop()
		case <-stop:
			tick.Stop()
			return
		}
	}
}

// pull 执行一次拉取，返回是否有变更。
func (s *Syncer) pull() (bool, error) {
	s.mu.Lock()
	cfg := s.cfg // 快照，避免与 Reconfigure 并发竞争
	s.mu.Unlock()
	var defs []Def
	var err error
	switch cfg.Mode {
	case "git":
		defs, err = s.pullGit(cfg)
	case "raw":
		defs, err = s.pullRaw(cfg)
	default:
		return false, fmt.Errorf("未知同步模式: %s", cfg.Mode)
	}
	if err != nil {
		return false, err
	}

	s.mu.Lock()
	old := s.synced
	s.mu.Unlock()
	if sameDefs(old, defs) {
		return false, nil // 无变更
	}
	// 校验全部规则后才落盘缓存（防半截数据）
	for i := range defs {
		if err := defs[i].validate(); err != nil {
			return false, fmt.Errorf("远端规则 %s 校验失败: %v", orName(defs[i]), err)
		}
	}
	if err := s.saveCache(defs); err != nil {
		return false, fmt.Errorf("写缓存失败: %v", err)
	}
	s.mu.Lock()
	s.synced = defs
	s.mu.Unlock()
	return true, nil
}

// pullGit clone/pull 仓库并解析规则：优先遍历仓库 rules/ 子目录，兼容旧版根目录布局。
func (s *Syncer) pullGit(cfg RepoConfig) ([]Def, error) {
	if _, statErr := os.Stat(filepath.Join(s.repoDir, ".git")); statErr != nil {
		// 首次 clone
		args := []string{"clone", "--depth", "1", "--single-branch", "-b", cfg.Branch, cfg.Repo, s.repoDir}
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("git clone 失败: %v: %s", err, truncate(string(out), 200))
		}
	} else {
		// 拉取更新；失败(网络/冲突)则丢弃本地状态重新 clone
		args := []string{"-C", s.repoDir, "fetch", "--depth", "1", "origin", cfg.Branch}
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			_ = os.RemoveAll(s.repoDir)
			return nil, fmt.Errorf("git fetch 失败(下次将重新clone): %v: %s", err, truncate(string(out), 200))
		}
		args = []string{"-C", s.repoDir, "reset", "--hard", "-q", "FETCH_HEAD"}
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			_ = os.RemoveAll(s.repoDir)
			return nil, fmt.Errorf("git reset 失败(下次将重新clone): %v: %s", err, truncate(string(out), 200))
		}
	}
	return parseRepoRules(s.repoDir)
}

// parseRepoRules 优先解析仓库 rules/ 子目录（递归遍历，可分子目录分类），
// 目录不存在时回退到旧版布局：只扫描仓库根目录的 yaml。
func parseRepoRules(repoDir string) ([]Def, error) {
	rulesPath := filepath.Join(repoDir, repoRulesDir)
	if st, err := os.Stat(rulesPath); err == nil && st.IsDir() {
		defs, perr := parseRulesTree(rulesPath)
		if perr != nil {
			return nil, fmt.Errorf("解析 %s/ 目录失败: %v", repoRulesDir, perr)
		}
		if len(defs) == 0 {
			return nil, fmt.Errorf("%s/ 目录下未解析到规则", repoRulesDir)
		}
		return defs, nil
	}
	return parseDirRules(repoDir)
}

// pullRaw 纯 HTTP 拉取（节点无需安装 git）。
// repo 为单个文件 URL（Files 为空）或目录前缀（Files 非空时逐个文件拉取合并）。
// 适配各 Git 服务器的 raw 地址，如：
//   GitHub:  https://raw.githubusercontent.com/user/repo/main
//   Gitea:   https://host/team/repo/raw/branch/main
//   GitLab:  https://host/team/repo/-/raw/main
func (s *Syncer) pullRaw(cfg RepoConfig) ([]Def, error) {
	urls := rawURLs(cfg)
	var all []Def
	for _, u := range urls {
		data, err := s.fetchRawFile(cfg, u)
		if err != nil {
			return nil, fmt.Errorf("拉取 %s 失败: %v", maskURL(u), err)
		}
		defs, perr := parseRulesData(data)
		if perr != nil {
			// 单文件模式下格式错误要报错；列表模式下跳过非规则文件
			if len(cfg.Files) == 0 {
				return nil, fmt.Errorf("%s 不是规则格式: %v", maskURL(u), perr)
			}
			continue
		}
		all = append(all, defs...)
	}
	if len(all) == 0 && len(cfg.Files) > 0 {
		return nil, fmt.Errorf("未从任何文件解析到规则")
	}
	return all, nil
}

// rawURLs 生成待拉取的 URL 列表。
func rawURLs(cfg RepoConfig) []string {
	base := strings.TrimRight(cfg.Repo, "/")
	if len(cfg.Files) == 0 {
		return []string{base}
	}
	urls := make([]string, 0, len(cfg.Files))
	for _, f := range cfg.Files {
		f = strings.TrimLeft(strings.TrimSpace(f), "/")
		if f == "" {
			continue
		}
		urls = append(urls, base+"/"+f)
	}
	return urls
}

// fetchRawFile 带认证头 GET 单个文件。
func (s *Syncer) fetchRawFile(cfg RepoConfig, u string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	if cfg.Token != "" {
		h := cfg.AuthHeader
		if h == "" {
			h = "Authorization: Bearer {token}"
		}
		h = strings.ReplaceAll(h, "{token}", cfg.Token)
		if i := strings.Index(h, ":"); i > 0 {
			req.Header.Set(strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]))
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil {
			break
		}
		if len(buf) > 4*1024*1024 {
			return nil, fmt.Errorf("文件超过 4MB 上限")
		}
	}
	return buf, nil
}

// parseRulesTree 递归遍历规则目录（跳过隐藏目录）解析全部 .yaml/.yml 规则文件；
// 非规则格式的 yaml 直接跳过，便于目录里放 README 等说明文件。
func parseRulesTree(root string) ([]Def, error) {
	var all []Def
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		defs, perr := parseRulesData(data)
		if perr != nil {
			return nil
		}
		all = append(all, defs...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

// parseDirRules 解析目录下所有 .yaml/.yml 规则文件（子目录不递归，兼容旧版仓库根目录布局）。
func parseDirRules(dir string) ([]Def, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var all []Def
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		defs, perr := parseRulesData(data)
		if perr != nil {
			// 不是规则格式的 yaml（如 README 配置）直接跳过
			continue
		}
		all = append(all, defs...)
	}
	return all, nil
}

// defWire 远端规则的序列化中间类型：Enabled 用指针区分"未写"与"显式停用"。
type defWire struct {
	ID       string   `yaml:"id"`
	Kind     string   `yaml:"kind"`
	Score    int      `yaml:"score"`
	Desc     string   `yaml:"desc"`
	Pattern  string   `yaml:"pattern"`
	Patterns []string `yaml:"patterns"`
	Enabled  *bool    `yaml:"enabled"`
}

// parseRulesData 尝试把 yaml 数据解析为规则数组或单条规则。
// 共享规则未显式写 enabled 时默认启用（与本地库"新增即启用"一致）。
func parseRulesData(data []byte) ([]Def, error) {
	var wires []defWire
	if err := yaml.Unmarshal(data, &wires); err == nil && len(wires) > 0 && wires[0].Kind != "" {
		return wireToDefs(wires), nil
	}
	var w defWire
	if err := yaml.Unmarshal(data, &w); err == nil && w.Kind != "" &&
		(w.Pattern != "" || len(w.Patterns) > 0) {
		return wireToDefs([]defWire{w}), nil
	}
	return nil, fmt.Errorf("非规则格式")
}

func wireToDefs(wires []defWire) []Def {
	defs := make([]Def, 0, len(wires))
	for _, w := range wires {
		enabled := true
		if w.Enabled != nil {
			enabled = *w.Enabled
		}
		defs = append(defs, Def{
			ID: w.ID, Kind: w.Kind, Score: w.Score, Desc: w.Desc,
			Pattern: w.Pattern, Patterns: w.Patterns, Enabled: enabled,
		})
	}
	return defs
}

func sameDefs(a, b []Def) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Score != b[i].Score || a[i].Pattern != b[i].Pattern ||
			a[i].Enabled != b[i].Enabled || a[i].Kind != b[i].Kind ||
			strings.Join(a[i].Patterns, "\x00") != strings.Join(b[i].Patterns, "\x00") {
			return false
		}
	}
	return true
}

func (s *Syncer) saveCache(defs []Def) error {
	data, err := yaml.Marshal(defs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.cachePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.cachePath, data, 0o644)
}

// LoadCache 启动时从缓存文件恢复共享规则（断源兜底）。
func (s *Syncer) LoadCache() {
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		return
	}
	defs, err := parseRulesData(data)
	if err != nil {
		return
	}
	out := defs[:0]
	for i := range defs {
		if defs[i].validate() == nil {
			out = append(out, defs[i])
		}
	}
	s.mu.Lock()
	s.synced = out
	s.mu.Unlock()
}

// MergeRules 合并共享规则与本地规则：按 ID 去重，本地优先（便于单机覆盖微调）。
func MergeRules(local, remote []*detector.Rule) []*detector.Rule {
	seen := map[string]bool{}
	out := make([]*detector.Rule, 0, len(local)+len(remote))
	for _, r := range local {
		seen[r.ID] = true
		out = append(out, r)
	}
	for _, r := range remote {
		if !seen[r.ID] {
			out = append(out, r)
		}
	}
	return out
}