package webui

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
	"webshell-guard/internal/rules"
)

func TestRulesAddThenUpdateByRuleID(t *testing.T) {
	dir := t.TempDir()
	s := &Server{
		cfg:       &config.Config{LogFile: filepath.Join(dir, "g.log")},
		det:       detector.New(6, nil, nil),
		ruleStore: rules.New(filepath.Join(dir, "rules_custom.yaml")),
	}

	post := func(body string) map[string]any {
		req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleRules(rec, req)
		if rec.Code != 200 {
			t.Fatalf("状态 %d: %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	// 新增：只带 rule（不传顶层 id）
	add := post(`{"op":"add","rule":{"kind":"webshell","score":7,"desc":"d","pattern":"ZZZ"}}`)
	ruleObj, _ := add["rule"].(map[string]any)
	id, _ := ruleObj["id"].(string)
	if id == "" {
		t.Fatal("新增未返回自动生成的 ID")
	}

	// 更新：只带 rule.id（旧前端不带顶层 id 的行为）
	post(`{"op":"update","rule":{"id":"` + id + `","kind":"webshell","score":8,"desc":"d2","pattern":"ZZZ"}}`)

	list := s.ruleStore.List()
	if len(list) != 1 || list[0].Score != 8 || list[0].Desc != "d2" {
		t.Fatalf("按 rule.id 更新未生效: %+v", list)
	}
}
