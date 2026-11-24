package monitor

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"webshell-guard/internal/action"
	"webshell-guard/internal/aijudge"
	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
	"webshell-guard/internal/notify"
)

type aiEnv struct {
	engine *Engine
	judge  *aijudge.Judge
	cfg    *config.Config
	path   string
	calls  *int32
}

func newAIEnv(t *testing.T, content, answer string) *aiEnv {
	t.Helper()
	dir := t.TempDir()
	site := filepath.Join(dir, "site")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(site, "risky.aspx")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)

	cfg := &config.Config{
		WatchDirs:      []string{site},
		MaxFileSize:    1 << 20,
		ScoreThreshold: 6,
		Action:         "quarantine",
		QuarantineDir:  filepath.Join(dir, "quarantine"),
		LogFile:        filepath.Join(dir, "guard.log"),
		Baseline:       config.BaselineConfig{Enabled: true, File: filepath.Join(dir, "baseline.json")},
	}
	det := detector.New(6, nil, nil)
	baseline := detector.NewBaseline(cfg.Baseline.File)
	exec := action.New(cfg, notify.New(config.WebhookConfig{}, 0), baseline)
	judge, err := aijudge.New(aijudge.Config{
		Enabled: true, URL: srv.URL, AppKey: "dang888",
		WhitelistFile: filepath.Join(dir, "ai_whitelist.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(cfg, det, exec, baseline, judge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return &aiEnv{engine: engine, judge: judge, cfg: cfg, path: path, calls: &calls}
}

func TestAISafeWhitelistsAndSkipsAction(t *testing.T) {
	content := `<% eval(Request.Item["z"]); var b = System.Convert.FromBase64String("eA=="); %>`
	env := newAIEnv(t, content, "SAFE")
	ch := make(chan string, 4)

	env.engine.checkFile(env.path, "test", ch)

	if _, err := os.Stat(env.path); err != nil {
		t.Fatalf("AI 判定安全后文件不应被处置: %v", err)
	}
	if !env.judge.IsWhitelisted(detector.HashContent(content)) {
		t.Fatal("AI 判定安全后应加入白名单")
	}

	// 再次检测：白名单命中，直接跳过，不再请求 AI
	env.engine.checkFile(env.path, "test", ch)
	if n := atomic.LoadInt32(env.calls); n != 1 {
		t.Fatalf("白名单命中后不应重复请求 AI, 实际请求 %d 次", n)
	}
}

func TestAIMaliciousTriggersAction(t *testing.T) {
	// 只有风险字符、没有任何规则命中（score=0），AI 判恶意后也应处置
	content := `var p = System.Environment.GetEnvironmentVariable("PATH");`
	env := newAIEnv(t, content, "MALICIOUS")
	ch := make(chan string, 4)

	env.engine.checkFile(env.path, "test", ch)

	if _, err := os.Stat(env.path); !os.IsNotExist(err) {
		t.Fatal("AI 判定恶意后文件应被隔离")
	}
	files, err := os.ReadDir(env.cfg.QuarantineDir)
	if err != nil || len(files) == 0 {
		t.Fatalf("隔离目录为空: %v", err)
	}
	// 历史里应记录本次处置
	hist, err := os.ReadFile(filepath.Join(filepath.Dir(env.cfg.LogFile), "alert_history.jsonl"))
	if err != nil || !strings.Contains(string(hist), "quarantine") {
		t.Fatalf("处置历史缺失: %v %s", err, hist)
	}
	if !strings.Contains(string(hist), "AI-JUDGE") || strings.Contains(string(hist), `"hits":null`) {
		t.Fatalf("AI 判恶应补一条命中记录且 hits 不为 null: %s", hist)
	}
}

func TestAIErrorKeepsRuleVerdict(t *testing.T) {
	// AI 接口返回 500：应沿用规则判定（此样本规则命中 → 隔离）
	env := newAIEnv(t, `<% eval(Request.Item["z"]); var b = System.Convert.FromBase64String("eA=="); %>`, "")
	// 换一个永远 500 的服务，验证 AI 失败时沿用规则判定
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	j, err := aijudge.New(aijudge.Config{
		Enabled: true, URL: srv.URL, AppKey: "dang888",
		WhitelistFile: filepath.Join(t.TempDir(), "wl.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	env.engine.ai = j

	ch := make(chan string, 4)
	env.engine.checkFile(env.path, "test", ch)
	if _, err := os.Stat(env.path); !os.IsNotExist(err) {
		t.Fatal("AI 失败时应沿用规则判定并隔离")
	}
}
