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

	h := History{
		Time:    alarm.Time,
		Orig:    absPath,
		Action:  act,
		NewPath: quarantinePathOf(detail),
		Hash:    res.SHA256,
		Score:   res.Score,
		Hits:    res.Hits,
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
	dst := filepath.Join(e.cfg.QuarantineDir, ts+"_"+filepath.ToSlash(rel))

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

// recordHistory 追加告警历史 JSONL。
func (e *Executor) recordHistory(h History) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := os.OpenFile(e.historyPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("[action] 写告警历史失败: %v", err)
		return
	}
	defer f.Close()
	data, _ := json.Marshal(h)
	f.Write(append(data, '\n'))
}

func quarantinePathOf(detail string) string {
	if i := strings.Index(detail, "→ "); i >= 0 {
		return strings.TrimSpace(detail[i+3:])
	}
	return ""
}
