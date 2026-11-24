package rules

import (
	"regexp"
	"testing"

	"webshell-guard/internal/detector"
)

func mustRe(s string) *regexp.Regexp { return regexp.MustCompile("(?i)" + s) }

func TestResolveBuiltinRulesOverrideAndDisable(t *testing.T) {
	defaults := []*detector.Rule{
		{ID: "A", Kind: detector.KindWebshell, Score: 5, Desc: "orig A", Pattern: mustRe("AAA")},
		{ID: "B", Kind: detector.KindWebshell, Score: 5, Desc: "orig B", Pattern: mustRe("BBB")},
	}
	off := false
	defs := []BuiltinDef{
		{ID: "A", Kind: "webshell", Score: 9, Desc: "patched A", Pattern: "NEW_A"},
		{ID: "B", Kind: "webshell", Score: 5, Desc: "disabled B", Pattern: "BBB", Enabled: &off},
		{ID: "C", Kind: "horse", Score: 7, Desc: "new C", Pattern: "CCC"},
	}
	got, err := ResolveBuiltinRules(defs, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("期望 2 条(A 覆盖 + C 新增, B 停用), 实际 %d", len(got))
	}
	if got[0].ID != "A" || got[0].Score != 9 || got[0].Pattern.String() != "(?i)NEW_A" {
		t.Fatalf("A 未正确覆盖: %+v", got[0])
	}
	if got[1].ID != "C" || got[1].Desc != "new C" {
		t.Fatalf("C 未正确新增: %+v", got[1])
	}
}

func TestOverrideBuiltinByDefs(t *testing.T) {
	base := []*detector.Rule{
		{ID: "A", Kind: detector.KindWebshell, Score: 5, Pattern: mustRe("AAA")},
		{ID: "B", Kind: detector.KindWebshell, Score: 5, Pattern: mustRe("BBB")},
	}
	defs := []Def{{ID: "A", Kind: "webshell", Score: 8, Desc: "patched", Pattern: "ZZZ"}}
	got := OverrideBuiltinByDefs(base, defs)
	if len(got) != 2 || got[0].Score != 8 || got[0].Pattern.String() != "(?i)ZZZ" || got[1].Score != 5 {
		t.Fatalf("按 ID 覆盖失败: %+v", got)
	}
	// 基线未被修改
	if base[0].Score != 5 {
		t.Fatal("覆盖了基线规则, 会导致重复叠加")
	}
}

func TestResolveBuiltinRulesDropsDeprecatedIDs(t *testing.T) {
	// 代码里已删除这两条规则；老 rules_builtin.yaml 里残留时也必须强制剔除
	defaults := []*detector.Rule{
		{ID: "HM-IFRAME-EXT", Kind: detector.KindHorse, Score: 5, Pattern: mustRe("<iframe")},
	}
	defs := []BuiltinDef{
		{ID: "HM-SCRIPT-EXT", Kind: "horse", Score: 3, Desc: "外部script引用", Pattern: "<script"},
		{ID: "HM-DOC-WRITE-SCRIPT", Kind: "horse", Score: 5, Desc: "document.write 注入外链", Pattern: "document\\.write"},
	}
	got, err := ResolveBuiltinRules(defs, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "HM-IFRAME-EXT" {
		t.Fatalf("已下线规则应从内置规则集剔除: %+v", got)
	}
}

func TestMergeDefsLocalPriority(t *testing.T) {
	local := []Def{{ID: "A", Desc: "local"}}
	remote := []Def{{ID: "A", Desc: "remote"}, {ID: "B", Desc: "remote B"}}
	got := MergeDefs(local, remote)
	if len(got) != 2 || got[0].Desc != "local" || got[1].ID != "B" {
		t.Fatalf("合并结果错误: %+v", got)
	}
}

func TestBuiltinRoundTrip(t *testing.T) {
	defaults := []*detector.Rule{
		{ID: "A", Kind: detector.KindWebshell, Score: 5, Desc: "single", Pattern: mustRe("AAA")},
		{ID: "B", Kind: detector.KindHorse, Score: 6, Desc: "combo", Combination: true,
			PatternAll: []*regexp.Regexp{mustRe("BBB"), mustRe("CCC")}},
	}
	defs := BuiltinRulesToDefs(defaults)
	if len(defs) != 2 || defs[0].Pattern != "(?i)AAA" || len(defs[1].Patterns) != 2 {
		t.Fatalf("导出格式错误: %+v", defs)
	}
	got, err := defsToBuiltinRules(defs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Pattern.String() != "(?i)AAA" || len(got[1].PatternAll) != 2 {
		t.Fatalf("往返后规则不一致: %+v", got)
	}
}
