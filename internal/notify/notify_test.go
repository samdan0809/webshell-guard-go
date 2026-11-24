package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
)

func TestMarkdownKeepsWindowsBackslashes(t *testing.T) {
	a := Alert{
		Time: "2026-11-24 08:21:38", Host: "iZk0pvjc5rs6e9Z",
		File: `D:\wwwroot\colorpantone\1.aspx`, Action: "quarantine", Score: 6,
		SHA256: "27ad0819",
		Hits:   []detector.Hit{{RuleID: "AI-JUDGE", Kind: "webshell", Score: 0, Desc: "AI 判定恶意(无规则命中)", Detail: `D:\wwwroot\colorpantone\1.aspx`}},
	}
	n := New(config.WebhookConfig{Type: "dingtalk", URL: "http://127.0.0.1:1"}, 0)

	payload := n.buildPayload(config.WebhookConfig{Type: "dingtalk", URL: "http://127.0.0.1:1"}, a)
	var m struct {
		Markdown struct {
			Text string `json:"text"`
		} `json:"markdown"`
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Markdown.Text, `D:\\wwwroot\\colorpantone\\1.aspx`) {
		t.Fatalf("markdown 里路径反斜杠未转义: %s", m.Markdown.Text)
	}

	// 企微 markdown 同样处理
	payload = n.buildPayload(config.WebhookConfig{Type: "wecom", URL: "http://127.0.0.1:1"}, a)
	var w struct {
		Markdown struct {
			Content string `json:"content"`
		} `json:"markdown"`
	}
	if err := json.Unmarshal(payload, &w); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.Markdown.Content, `D:\\wwwroot\\colorpantone\\1.aspx`) {
		t.Fatalf("企微 markdown 里路径反斜杠未转义: %s", w.Markdown.Content)
	}

	// 飞书 text 模式保持原样，不重复转义
	payload = n.buildPayload(config.WebhookConfig{Type: "feishu", URL: "http://127.0.0.1:1"}, a)
	var f struct {
		Content struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(payload, &f); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Content.Text, `D:\wwwroot\colorpantone\1.aspx`) {
		t.Fatalf("text 模式路径不应被改写: %s", f.Content.Text)
	}
	if strings.Contains(f.Content.Text, `\\`) {
		t.Fatal("text 模式不应出现双反斜杠")
	}
}
