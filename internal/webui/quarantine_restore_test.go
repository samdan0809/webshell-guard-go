package webui

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webshell-guard/internal/action"
	"webshell-guard/internal/aijudge"
	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
	"webshell-guard/internal/notify"
)

// quarantineFixture 造一个真实隔离场景：站点里放一个恶意文件，由 Executor 隔离。
type quarantineFixture struct {
	dir      string
	orig     string
	cfg      *config.Config
	histPath string
	srv      *Server
}

func newQuarantineFixture(t *testing.T) *quarantineFixture {
	t.Helper()
	dir := t.TempDir()
	site := filepath.Join(dir, "site")
	if err := os.MkdirAll(filepath.Join(site, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := filepath.Join(site, "sub", "shell.aspx")
	if err := os.WriteFile(orig, []byte(`eval(Request.Item["z"])`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		WatchDirs:      []string{site},
		QuarantineDir:  filepath.Join(dir, "quarantine"),
		LogFile:        filepath.Join(dir, "guard.log"),
		Action:         "quarantine",
		ScoreThreshold: 6,
	}
	det := detector.New(6, nil, nil)
	exec := action.New(cfg, notify.New(config.WebhookConfig{}, 0), nil)
	data, err := os.ReadFile(orig)
	if err != nil {
		t.Fatal(err)
	}
	res := det.Detect(string(data), int64(len(data)))
	if res.Clean {
		t.Fatalf("样本未被判定为恶意: %+v", res)
	}
	if _, err := exec.Handle(orig, res, false); err != nil {
		t.Fatalf("隔离失败: %v", err)
	}
	return &quarantineFixture{
		dir:      dir,
		orig:     orig,
		cfg:      cfg,
		histPath: filepath.Join(dir, "alert_history.jsonl"),
		srv:      &Server{cfg: cfg, det: det, histPath: filepath.Join(dir, "alert_history.jsonl")},
	}
}

func (f *quarantineFixture) quarantined(t *testing.T) string {
	t.Helper()
	files := f.srv.listQuarantine()
	if len(files) != 1 {
		t.Fatalf("隔离区应有 1 个文件(索引文件不应计入), 实际 %d: %+v", len(files), files)
	}
	return files[0].Name
}

func TestQuarantineHistoryAndRestore(t *testing.T) {
	f := newQuarantineFixture(t)
	name := f.quarantined(t)

	if len(f.srv.readHistory()) != 1 {
		t.Fatalf("告警历史应有 1 条: %+v", f.srv.readHistory())
	}
	if got := f.srv.findOrig(name); got != f.orig {
		t.Fatalf("findOrig=%q, want %q", got, f.orig)
	}

	body := `{"op":"restore","name":"` + name + `"}`
	rec := httptest.NewRecorder()
	f.srv.handleAction(rec, httptest.NewRequest("POST", "/api/action", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("恢复失败 %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(f.orig); err != nil {
		t.Fatalf("文件未恢复到原路径: %v", err)
	}
}

func TestRestoreFallsBackToQuarantineIndex(t *testing.T) {
	f := newQuarantineFixture(t)
	name := f.quarantined(t)

	// 模拟告警历史被清理/写到了别处：删掉历史文件，只剩隔离区索引
	if err := os.Remove(f.histPath); err != nil {
		t.Fatal(err)
	}
	if got := f.srv.findOrig(name); got != f.orig {
		t.Fatalf("历史缺失时应由隔离索引兜底, got=%q want=%q", got, f.orig)
	}

	body := `{"op":"restore","name":"` + name + `"}`
	rec := httptest.NewRecorder()
	f.srv.handleAction(rec, httptest.NewRequest("POST", "/api/action", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("索引兜底恢复失败 %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(f.orig); err != nil {
		t.Fatalf("文件未恢复到原路径: %v", err)
	}
}

func TestRestoreWithManualOrigWhenNoRecord(t *testing.T) {
	f := newQuarantineFixture(t)
	name := f.quarantined(t)

	// 历史与索引都清掉：只能靠用户手填原路径
	_ = os.Remove(f.histPath)
	_ = os.Remove(filepath.Join(f.cfg.QuarantineDir, action.QuarantineIndexFile))

	payload, _ := json.Marshal(map[string]string{"op": "restore", "name": name, "orig": f.orig})
	rec := httptest.NewRecorder()
	f.srv.handleAction(rec, httptest.NewRequest("POST", "/api/action", strings.NewReader(string(payload))))
	if rec.Code != 200 {
		t.Fatalf("手填路径恢复失败 %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(f.orig); err != nil {
		t.Fatalf("文件未恢复到原路径: %v", err)
	}
}

func TestRestoreAddsWhitelist(t *testing.T) {
	f := newQuarantineFixture(t)
	j, err := aijudge.New(aijudge.Config{
		Enabled: true, URL: "http://127.0.0.1:1", AppKey: "dang888",
		WhitelistFile: filepath.Join(f.dir, "ai_whitelist.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv.judge = j
	name := f.quarantined(t)

	body := `{"op":"restore","name":"` + name + `"}`
	rec := httptest.NewRecorder()
	f.srv.handleAction(rec, httptest.NewRequest("POST", "/api/action", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("恢复失败 %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["whitelisted"] != true {
		t.Fatalf("恢复应返回 whitelisted=true: %v", out)
	}
	// 恢复的内容必须按哈希进白名单，否则文件一落地又会被同一规则隔离
	if !j.IsWhitelisted(detector.HashContent(`eval(Request.Item["z"])`)) {
		t.Fatal("恢复后未加入白名单")
	}
	if got := j.Whitelist(); len(got) != 1 || got[0].Reason != "manual-restore" {
		t.Fatalf("白名单来源应标记 manual-restore: %+v", got)
	}
}

func TestRestoreRejectsRelativeOrig(t *testing.T) {
	f := newQuarantineFixture(t)
	name := f.quarantined(t)
	_ = os.Remove(f.histPath)
	_ = os.Remove(filepath.Join(f.cfg.QuarantineDir, action.QuarantineIndexFile))

	payload, _ := json.Marshal(map[string]string{"op": "restore", "name": name, "orig": "relative/shell.aspx"})
	rec := httptest.NewRecorder()
	f.srv.handleAction(rec, httptest.NewRequest("POST", "/api/action", strings.NewReader(string(payload))))
	if rec.Code != 400 {
		t.Fatalf("相对路径应被拒绝, 实际 %d", rec.Code)
	}
}
