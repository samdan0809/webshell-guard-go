package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"webshell-guard/internal/aijudge"
	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
	"webshell-guard/internal/rules"
)

func TestAITestEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":"SAFE"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	j, err := aijudge.New(aijudge.Config{
		Enabled: true, URL: srv.URL, AppKey: "dang888",
		WhitelistFile: filepath.Join(dir, "ai_whitelist.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg:       &config.Config{LogFile: filepath.Join(dir, "g.log")},
		det:       detector.New(6, nil, nil),
		ruleStore: rules.New(filepath.Join(dir, "rules_custom.yaml")),
		judge:     j,
	}

	rec := httptest.NewRecorder()
	s.handleAITest(rec, httptest.NewRequest("POST", "/api/aitest", nil))
	if rec.Code != 200 {
		t.Fatalf("状态 %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true {
		t.Fatalf("期望 ok=true: %v", out)
	}
	if out["verdict"] != "safe" || out["answer"] != "SAFE" {
		t.Fatalf("返回内容异常: %v", out)
	}

	// 只允许 POST
	rec = httptest.NewRecorder()
	s.handleAITest(rec, httptest.NewRequest("GET", "/api/aitest", nil))
	if rec.Code != 405 {
		t.Fatalf("GET 应返回 405, 实际 %d", rec.Code)
	}
}

func TestAITestEndpointDisabled(t *testing.T) {
	dir := t.TempDir()
	j, err := aijudge.New(aijudge.Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg:       &config.Config{LogFile: filepath.Join(dir, "g.log")},
		det:       detector.New(6, nil, nil),
		ruleStore: rules.New(filepath.Join(dir, "rules_custom.yaml")),
		judge:     j,
	}
	rec := httptest.NewRecorder()
	s.handleAITest(rec, httptest.NewRequest("POST", "/api/aitest", nil))
	if rec.Code != 200 {
		t.Fatalf("状态 %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != false || out["error"] == nil || out["error"] == "" {
		t.Fatalf("未启用时应返回 ok=false + error: %v", out)
	}
}
