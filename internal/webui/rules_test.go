package webui

import "testing"

func TestParseRulesTextJSONAndYAML(t *testing.T) {
	cases := map[string]string{
		"JSON数组": `[{"kind":"webshell","score":7,"desc":"d","pattern":"x"}]`,
		"JSON单条": `{"kind":"horse","score":5,"desc":"d","pattern":"y"}`,
		"YAML数组": "- kind: webshell\n  score: 7\n  desc: d\n  pattern: x\n",
		"YAML单条": "kind: horse\nscore: 5\ndesc: d\npattern: y\n",
	}
	for name, raw := range cases {
		defs, err := parseRulesText(raw)
		if err != nil {
			t.Fatalf("%s 解析失败: %v", name, err)
		}
		if len(defs) != 1 {
			t.Fatalf("%s 期望 1 条, 实际 %d", name, len(defs))
		}
	}
}

func TestParseRulesTextInvalid(t *testing.T) {
	if _, err := parseRulesText("这不是规则"); err == nil {
		t.Fatal("非法内容应报错")
	}
}
