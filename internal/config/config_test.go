package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAllowsEmptyWatchDirs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("watch_dirs: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("watch_dirs 为空应允许加载: %v", err)
	}
	if len(cfg.WatchDirs) != 0 {
		t.Fatalf("期望空目录列表, 实际 %v", cfg.WatchDirs)
	}
}

func TestLoadRejectsMissingWatchDir(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("watch_dirs:\n  - /nonexistent/path/for/test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("填了不存在的目录应报错")
	}
}
