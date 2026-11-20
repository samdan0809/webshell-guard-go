package action

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webshell-guard/internal/config"
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
