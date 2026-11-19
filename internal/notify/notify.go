// Package notify 实现 webhook 告警。
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
)

// Alert 告警消息体。
type Alert struct {
	Time    string        `json:"time"`
	Host    string        `json:"host"`
	File    string        `json:"file"`
	Action  string        `json:"action"` // quarantine | delete | alert
	SHA256  string        `json:"sha256"`
	Size    int64         `json:"size"`
	Score   int           `json:"score"`
	Hits    []detector.Hit `json:"hits"`
}

// Notifier webhook 发送器。
type Notifier struct {
	cfg      config.WebhookConfig
	client   *http.Client
	mu       sync.Mutex
	lastSent map[string]time.Time // 文件 -> 上次告警时间（频控）
}

// New 创建 Notifier。
func New(cfg config.WebhookConfig, cooldown time.Duration) *Notifier {
	return &Notifier{
		cfg:      cfg,
		client:   &http.Client{Timeout: time.Duration(cfg.Timeout) * time.Second},
		lastSent: map[string]time.Time{},
	}
}

// SetURL 运行时更新 webhook 地址。
func (n *Notifier) SetURL(url string) {
	n.mu.Lock()
	n.cfg.URL = url
	n.mu.Unlock()
}

// SetType 运行时更新消息模板类型。
func (n *Notifier) SetType(t string) {
	n.mu.Lock()
	n.cfg.Type = t
	n.mu.Unlock()
}

// Send 推送告警（带频控与重试）。返回是否真正发出。
func (n *Notifier) Send(a Alert, cooldown time.Duration) bool {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	if cfg.URL == "" {
		return false
	}
	n.mu.Lock()
	if t, ok := n.lastSent[a.File]; ok && time.Since(t) < cooldown {
		n.mu.Unlock()
		return false
	}
	n.lastSent[a.File] = time.Now()
	// 简单清理：只保留最近 1000 条
	if len(n.lastSent) > 1000 {
		n.lastSent = map[string]time.Time{}
	}
	n.mu.Unlock()

	payload := n.buildPayload(cfg, a)
	var lastErr error
	for i := 0; i <= cfg.Retry; i++ {
		if i > 0 {
			time.Sleep(time.Duration(1<<uint(i-1)) * time.Second) // 1s,2s,4s...
		}
		if err := n.post(payload); err != nil {
			lastErr = err
			log.Printf("[notify] 第%d次发送失败: %v", i+1, err)
			continue
		}
		return true
	}
	log.Printf("[notify] webhook 发送最终失败(已重试%d次): %v", cfg.Retry, lastErr)
	return false
}

// post 实际 HTTP POST。
func (n *Notifier) post(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, n.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook 返回状态码 %d", resp.StatusCode)
	}
	return nil
}

// buildPayload 按类型包装请求体。
func (n *Notifier) buildPayload(cfg config.WebhookConfig, a Alert) []byte {
	text := fmt.Sprintf(
		"【webshell-guard 告警】\n时间: %s\n主机: %s\n文件: %s\n处置: %s\n评分: %d\nSHA256: %s\n规则: %s",
		a.Time, a.Host, a.File, a.Action, a.Score, a.SHA256, hitsSummary(a.Hits),
	)

	switch cfg.Type {
	case "dingtalk":
		b, _ := json.Marshal(map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"title": "webshell-guard 告警",
				"text":  "## webshell-guard 告警\n" + mdDetail(a),
			},
		})
		return b
	case "feishu":
		b, _ := json.Marshal(map[string]any{
			"msg_type": "text",
			"content":  map[string]string{"text": text},
		})
		return b
	case "wecom":
		b, _ := json.Marshal(map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"content": "**webshell-guard 告警**\n" + mdDetail(a),
			},
		})
		return b
	default: // generic：直接发结构化 JSON
		b, _ := json.MarshalIndent(a, "", "  ")
		return b
	}
}

func mdDetail(a Alert) string {
	s := fmt.Sprintf("- 时间: %s\n- 主机: %s\n- 文件: `%s`\n- 处置: **%s**\n- 评分: %d\n- SHA256: `%s`\n**命中规则:**\n",
		a.Time, a.Host, a.File, a.Action, a.Score, a.SHA256)
	for _, h := range a.Hits {
		s += fmt.Sprintf("- [%s+%d] %s (行%d) %s\n", h.RuleID, h.Score, h.Desc, h.Line, h.Detail)
	}
	return s
}

func hitsSummary(hits []detector.Hit) string {
	out := ""
	for i, h := range hits {
		if i > 0 {
			out += "; "
		}
		out += fmt.Sprintf("%s(+%d,%s)", h.RuleID, h.Score, string(h.Kind))
	}
	return out
}
