package webui

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
	"webshell-guard/internal/rules"
)

// fakeReloader 记录被触发的全量扫描来源。
type fakeReloader struct {
	ch chan string
}

func (f *fakeReloader) ReconfigureDirs([]string) {}

func (f *fakeReloader) ScanNow(source string) bool {
	f.ch <- source
	return true
}

func newScanTestServer(t *testing.T) (*Server, *fakeReloader) {
	t.Helper()
	dir := t.TempDir()
	fr := &fakeReloader{ch: make(chan string, 8)}
	return &Server{
		cfg:       &config.Config{LogFile: filepath.Join(dir, "g.log")},
		det:       detector.New(6, nil, nil),
		ruleStore: rules.New(filepath.Join(dir, "rules_custom.yaml")),
		reloader:  fr,
	}, fr
}

func waitScan(t *testing.T, fr *fakeReloader) string {
	t.Helper()
	select {
	case src := <-fr.ch:
		return src
	case <-time.After(2 * time.Second):
		t.Fatal("2s 内未触发全量扫描")
		return ""
	}
}

func TestScanEndpointTriggersFullScan(t *testing.T) {
	s, fr := newScanTestServer(t)

	req := httptest.NewRequest("POST", "/api/scan", nil)
	rec := httptest.NewRecorder()
	s.handleScan(rec, req)
	if rec.Code != 200 {
		t.Fatalf("状态 %d: %s", rec.Code, rec.Body.String())
	}
	if src := waitScan(t, fr); src != "manual" {
		t.Fatalf("扫描来源应为 manual, 实际 %q", src)
	}

	req = httptest.NewRequest("GET", "/api/scan", nil)
	rec = httptest.NewRecorder()
	s.handleScan(rec, req)
	if rec.Code != 405 {
		t.Fatalf("GET 应返回 405, 实际 %d", rec.Code)
	}
}

func TestRuleAddTriggersRescan(t *testing.T) {
	s, fr := newScanTestServer(t)

	req := httptest.NewRequest("POST", "/api/rules",
		strings.NewReader(`{"op":"add","rule":{"kind":"webshell","score":6,"desc":"d","keywords":["eval","FromBase64String"]}}`))
	rec := httptest.NewRecorder()
	s.handleRules(rec, req)
	if rec.Code != 200 {
		t.Fatalf("状态 %d: %s", rec.Code, rec.Body.String())
	}
	if src := waitScan(t, fr); src != "rule-add" {
		t.Fatalf("扫描来源应为 rule-add, 实际 %q", src)
	}
}
