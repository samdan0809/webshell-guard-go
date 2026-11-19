package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRepoRulesPrefersRulesDir(t *testing.T) {
	root := t.TempDir()
	writeRuleFile(t, filepath.Join(root, "legacy.yaml"), "LEGACY")

	rulesDir := filepath.Join(root, repoRulesDir)
	writeRuleFile(t, filepath.Join(rulesDir, "shared.yaml"), "NEW-A")
	writeRuleFile(t, filepath.Join(rulesDir, "php", "family.yaml"), "NEW-B")
	writeRuleFile(t, filepath.Join(rulesDir, ".hidden", "ignored.yaml"), "HIDDEN")
	if err := os.WriteFile(filepath.Join(rulesDir, "README.yaml"), []byte("not: rules\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	defs, err := parseRepoRules(root)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, d := range defs {
		ids[d.ID] = true
	}
	if len(defs) != 2 || !ids["NEW-A"] || !ids["NEW-B"] {
		t.Fatalf("期望只解析 rules/ 下两条规则，实际: %+v", defs)
	}
}

func TestParseRepoRulesFallbackToRoot(t *testing.T) {
	root := t.TempDir()
	writeRuleFile(t, filepath.Join(root, "legacy.yaml"), "LEGACY")

	defs, err := parseRepoRules(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) != 1 || defs[0].ID != "LEGACY" {
		t.Fatalf("期望回退解析根目录规则，实际: %+v", defs)
	}
}

func TestParseRepoRulesEmptyRulesDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, repoRulesDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := parseRepoRules(root); err == nil {
		t.Fatal("rules/ 目录存在但无规则时应报错，避免静默清空防护")
	}
}

func writeRuleFile(t *testing.T, path, id string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data := "- id: \"" + id + "\"\n  kind: webshell\n  score: 8\n  desc: test\n  pattern: TEST_PATTERN_" + id + "\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
