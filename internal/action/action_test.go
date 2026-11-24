package action

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
	"webshell-guard/internal/notify"
)

func TestQuarantineAddsBlockedSuffix(t *testing.T) {
	dir, err := os.MkdirTemp("", "wg-quar-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	srcDir := filepath.Join(dir, "site")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(srcDir, "shell.php")
	if err := os.WriteFile(src, []byte("harmless test content"), 0o644); err != nil {
		t.Fatal(err)
	}
	qdir := filepath.Join(dir, "quarantine")
	cfg := &config.Config{WatchDirs: []string{srcDir}, QuarantineDir: qdir, LogFile: filepath.Join(dir, "guard.log")}
	e := New(cfg, notify.New(config.WebhookConfig{}, 0), nil)

	dst, err := e.quarantine(src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(dst, ".blocked") {
		t.Fatalf("隔离文件名应带 .blocked 后缀: %s", dst)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("原文件未被移走")
	}
	if data, err := os.ReadFile(dst); err != nil || !strings.Contains(string(data), "harmless") {
		t.Fatalf("隔离文件内容丢失: %v", err)
	}
}

func TestHandleNormalizesNilHits(t *testing.T) {
	dir := t.TempDir()
	site := filepath.Join(dir, "site")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(site, "x.aspx")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		WatchDirs: []string{site}, QuarantineDir: filepath.Join(dir, "q"),
		LogFile: filepath.Join(dir, "g.log"), Action: "alert",
	}
	e := New(cfg, notify.New(config.WebhookConfig{}, 0), nil)

	// Hits 为 nil 时必须落成 []，否则前端 chipsHTML 会 null.map 报错、面板卡在"加载中"
	if _, err := e.Handle(file, detector.Result{Score: 6, SHA256: "abc"}, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "alert_history.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"hits":null`) {
		t.Fatalf("历史里 hits 不应为 null: %s", data)
	}
	if !strings.Contains(string(data), `"hits":[]`) {
		t.Fatalf("历史里 hits 应为空数组: %s", data)
	}
}
