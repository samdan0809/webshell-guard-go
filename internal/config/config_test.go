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

func TestLoadResolvesRelativePathsToConfigDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	content := "watch_dirs: []\nquarantine_dir: ./q\nbaseline:\n  file: ./b.json\nlog_file: ./g.log\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogFile != filepath.Join(dir, "g.log") {
		t.Fatalf("log_file 未解析到配置目录: %s", cfg.LogFile)
	}
	if cfg.QuarantineDir != filepath.Join(dir, "q") {
		t.Fatalf("quarantine_dir 未解析到配置目录: %s", cfg.QuarantineDir)
	}
	if cfg.Baseline.File != filepath.Join(dir, "b.json") {
		t.Fatalf("baseline.file 未解析到配置目录: %s", cfg.Baseline.File)
	}
}

func TestLoadResolvesDefaultLogFileToConfigDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("watch_dirs: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogFile != filepath.Join(dir, "webshell-guard.log") {
		t.Fatalf("默认 log_file 未解析到配置目录: %s", cfg.LogFile)
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
