package rules

import (
	"testing"

	"webshell-guard/internal/detector"
)

func TestKeywordsRuleAllMustAppear(t *testing.T) {
	d := Def{ID: "KW-TEST", Kind: "webshell", Score: 8, Desc: "关键字组合", Enabled: true,
		Keywords: []string{"ZZZKEY1", "ZZZKEY2"}}
	if err := d.validate(); err != nil {
		t.Fatalf("合法关键字组合被拒: %v", err)
	}
	rs := ToDetectorRules([]Def{d})
	if len(rs) != 1 || !rs[0].Combination {
		t.Fatalf("未转换为组合规则: %+v", rs)
	}

	det := detector.New(6, nil, nil)
	det.SetCustomRules(rs)

	// 两个关键字都出现 → 命中
	res := det.Detect("prefix ZZZKEY1 middle ZZZKEY2 suffix", 64)
	if res.Clean || res.Score < 6 {
		t.Fatalf("关键字同时出现应命中: score=%d hits=%v", res.Score, res.Hits)
	}

	// 只出现一个 → 不命中
	res2 := det.Detect("prefix ZZZKEY1 only", 64)
	if !res2.Clean {
		t.Fatalf("缺少关键字不应命中: score=%d hits=%v", res2.Score, res2.Hits)
	}
}

func TestKeywordsEscapesRegexMeta(t *testing.T) {
	d := Def{ID: "KW-META", Kind: "webshell", Score: 8, Desc: "特殊字符", Enabled: true,
		Keywords: []string{"ZZZ$KEY[1]", "ZZZEND"}}
	if err := d.validate(); err != nil {
		t.Fatal(err)
	}
	det := detector.New(6, nil, nil)
	det.SetCustomRules(ToDetectorRules([]Def{d}))

	// 关键字含正则元字符，应按纯文本匹配
	res := det.Detect("x ZZZ$KEY[1] y ZZZEND", 64)
	if res.Clean {
		t.Fatal("含正则元字符的关键字未按字面量匹配")
	}
}

func TestKeywordsValidation(t *testing.T) {
	cases := []Def{
		{ID: "K1", Kind: "webshell", Score: 5, Desc: "d", Keywords: []string{"only"}},           // 单关键字
		{ID: "K2", Kind: "webshell", Score: 5, Desc: "d", Keywords: []string{"a", " "}},          // 空关键字
		{ID: "K3", Kind: "webshell", Score: 5, Desc: "d", Pattern: "x", Keywords: []string{"a", "b"}}, // 混用
	}
	for _, c := range cases {
		if err := c.validate(); err == nil {
			t.Fatalf("应校验失败: %+v", c)
		}
	}
}
