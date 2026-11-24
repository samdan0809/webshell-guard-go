// Package action 实现处置动作：隔离/删除 + 告警历史落盘。
package action

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
	"webshell-guard/internal/notify"
)

// History 告警历史条目（JSONL 落盘）。
type History struct {
	Time    string         `json:"time"`
	Orig    string         `json:"orig_path"`
	Action  string         `json:"action"`
	NewPath string         `json:"new_path,omitempty"`
	Hash    string         `json:"sha256"`
	Score   int            `json:"score"`
	Hits    []detector.Hit `json:"hits"`
}

// QuarantineIndexFile 隔离区索引文件名（位于隔离区根目录）。
// 每次隔离都会登记"隔离文件 → 原路径"，告警历史 JSONL 被清理/迁移/写入失败时仍能恢复文件。
const QuarantineIndexFile = "quarantine_index.jsonl"

// QuarantineIndex 隔离索引条目。
type QuarantineIndex struct {
	Time    string `json:"time"`
	Orig    string `json:"orig_path"`
	NewPath string `json:"new_path"`
}

// Executor 处置器。
type Executor struct {
	cfg         *config.Config
	notifier    *notify.Notifier
	historyPath string
	mu          sync.Mutex
	baseline    BaselineEditor
	// OnHandled 每次处置完成后回调（供 Web UI 实时推送），在 goroutine 外同步调用。
	OnHandled func(History)
}

// BaselineEditor 基线操作的最小接口（避免循环依赖）。
type BaselineEditor interface {
	Remove(absPath string) error
}

type noopBaseline struct{}

func (noopBaseline) Remove(string) error { return nil }

// New 创建处置器。
func New(cfg *config.Config, n *notify.Notifier, baseline BaselineEditor) *Executor {
	if baseline == nil {
		baseline = noopBaseline{}
	}
	return &Executor{
		cfg:         cfg,
		notifier:    n,
		baseline:    baseline,
		historyPath: filepath.Join(filepath.Dir(cfg.LogFile), "alert_history.jsonl"),
	}
}

// Handle 对判定为恶意的文件执行处置并告警。返回处置结果描述。
func (e *Executor) Handle(absPath string, res detector.Result, inBaseline bool) (string, error) {
	act := e.cfg.Action
	var detail string
	var err error

	switch act {
	case "delete":
		err = os.Remove(absPath)
		detail = "已删除"
		if err == nil {
			_ = e.baseline.Remove(absPath)
		}
	case "quarantine":
		var newPath string
		newPath, err = e.quarantine(absPath)
		detail = "已隔离 → " + newPath
		if err == nil {
			_ = e.baseline.Remove(absPath)
		}
	case "alert":
		detail = "仅告警(文件未动)"
	default:
		err = fmt.Errorf("未知处置模式 %s", act)
	}

	host, _ := os.Hostname()
	alarm := notify.Alert{
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Host:   host,
		File:   absPath,
		Action: act,
		SHA256: res.SHA256,
		Size:   res.Size,
		Score:  res.Score,
		Hits:   res.Hits,
	}

	hits := res.Hits
	if hits == nil {
		hits = []detector.Hit{} // 避免 JSON 序列化成 null，前端渲染会炸
	}
	h := History{
		Time:    alarm.Time,
		Orig:    absPath,
		Action:  act,
		NewPath: quarantinePathOf(detail),
		Hash:    res.SHA256,
		Score:   res.Score,
		Hits:    hits,
	}
	e.recordHistory(h)
	if e.OnHandled != nil {
		e.OnHandled(h)
	}

	sent := e.notifier.Send(alarm, e.cfg.AlertCooldown)
	log.Printf("[action] %s | %s | score=%d | baseline=%v | webhook=%v",
		act, absPath, res.Score, inBaseline, sent)

	return detail, err
}

// quarantine 把文件移动到隔离目录，保留相对目录结构 + 时间戳前缀。
// 文件名末尾追加 .blocked，使隔离文件在网站目录下也不会被 Web 服务器解析执行。
func (e *Executor) quarantine(src string) (string, error) {
	// 找到文件所属的 watch root，以构造相对路径
	var rel string
	for _, root := range e.cfg.WatchDirs {
		if r, err := filepath.Rel(root, src); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
			break
		}
	}
	if rel == "" {
		rel = filepath.Base(src)
	}
	ts := time.Now().Format("20060102_150405")
	// 追加 .blocked 后缀：即使隔离目录被误配在网站根目录下，Web 服务器也不会把木马当脚本执行。
	dst := filepath.Join(e.cfg.QuarantineDir, ts+"_"+filepath.ToSlash(rel)+".blocked")

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	// 先重命名（同盘原子），失败则复制+删除
	if err := os.Rename(src, dst); err != nil {
		data, rerr := os.ReadFile(src)
		if rerr != nil {
			return "", fmt.Errorf("读取待隔离文件失败: %w", rerr)
		}
		if werr := os.WriteFile(dst, data, 0o644); werr != nil {
			return "", fmt.Errorf("写入隔离区失败: %w", werr)
		}
		if derr := os.Remove(src); derr != nil {
			return "", fmt.Errorf("隔离复制成功但删除原文件失败: %w", derr)
		}
	}
	log.Printf("[action] 隔离: %s -> %s", src, dst)
	return dst, nil
}

// recordHistory 追加告警历史 JSONL，并在隔离区索引里登记原路径。
func (e *Executor) recordHistory(h History) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := appendJSONLine(e.historyPath, h); err != nil {
		log.Printf("[action] 写告警历史失败(%s): %v", e.historyPath, err)
	}
	if h.NewPath == "" {
		return
	}
	entry := QuarantineIndex{Time: h.Time, Orig: h.Orig, NewPath: h.NewPath}
	if err := appendJSONLine(e.indexPath(), entry); err != nil {
		log.Printf("[action] 写隔离索引失败(%s): %v", e.indexPath(), err)
	}
}

// indexPath 隔离区索引文件路径。
func (e *Executor) indexPath() string {
	return filepath.Join(e.cfg.QuarantineDir, QuarantineIndexFile)
}

// appendJSONLine 以 JSONL 方式追加一行。
func appendJSONLine(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}

func quarantinePathOf(detail string) string {
	if i := strings.Index(detail, "→ "); i >= 0 {
		return strings.TrimSpace(detail[i+3:])
	}
	return ""
}
