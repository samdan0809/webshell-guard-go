package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"webshell-guard/internal/detector"
)

// BuiltinDef 内置规则的 yaml 表达（比 Def 多一个 enabled，用于停用某条内置规则）。
type BuiltinDef struct {
	ID       string   `yaml:"id" json:"id"`
	Kind     string   `yaml:"kind" json:"kind"`
	Score    int      `yaml:"score" json:"score"`
	Desc     string   `yaml:"desc" json:"desc"`
	Pattern  string   `yaml:"pattern,omitempty" json:"pattern"`
	Patterns []string `yaml:"patterns,omitempty" json:"patterns,omitempty"`
	Enabled  *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// BuiltinRulesToDefs 把 detector 规则导出为可编辑的 yaml 定义。
func BuiltinRulesToDefs(rs []*detector.Rule) []BuiltinDef {
	out := make([]BuiltinDef, 0, len(rs))
	for _, r := range rs {
		d := BuiltinDef{
			ID: r.ID, Kind: string(r.Kind), Score: r.Score, Desc: r.Desc,
		}
		if r.Combination {
			for _, p := range r.PatternAll {
				d.Patterns = append(d.Patterns, p.String())
			}
		} else if r.Pattern != nil {
			d.Pattern = r.Pattern.String()
		}
		on := true
		d.Enabled = &on
		out = append(out, d)
	}
	return out
}

// defsToBuiltinRules 把 yaml 定义编译为 detector 规则；enabled=false 的跳过。
func defsToBuiltinRules(defs []BuiltinDef) ([]*detector.Rule, error) {
	out := make([]*detector.Rule, 0, len(defs))
	for _, d := range defs {
		if d.Enabled != nil && !*d.Enabled {
			continue
		}
		r := &detector.Rule{ID: d.ID, Score: d.Score, Desc: d.Desc}
		switch d.Kind {
		case "horse", string(detector.KindHorse):
			r.Kind = detector.KindHorse
		default:
			r.Kind = detector.KindWebshell
		}
		if d.Pattern != "" && len(d.Patterns) > 0 {
			return nil, fmt.Errorf("规则 %s: pattern 与 patterns 二选一", d.ID)
		}
		compileCI := func(p string) (*regexp.Regexp, error) {
			// 导出时 Pattern.String() 已含 (?i)，避免重复叠加
			p = strings.TrimPrefix(p, "(?i)")
			return regexp.Compile("(?i)" + p)
		}
		if d.Pattern != "" {
			re, err := compileCI(d.Pattern)
			if err != nil {
				return nil, fmt.Errorf("规则 %s 正则非法: %v", d.ID, err)
			}
			r.Pattern = re
		} else if len(d.Patterns) > 0 {
			r.Combination = true
			for _, p := range d.Patterns {
				re, err := compileCI(p)
				if err != nil {
					return nil, fmt.Errorf("规则 %s 组合正则非法: %v", d.ID, err)
				}
				r.PatternAll = append(r.PatternAll, re)
			}
		} else {
			return nil, fmt.Errorf("规则 %s: 缺少 pattern/patterns", d.ID)
		}
		out = append(out, r)
	}
	return out, nil
}

// LoadBuiltinRules 读取内置规则 yaml（不存在返回 nil, nil，表示用代码默认）。
func LoadBuiltinRules(path string) ([]BuiltinDef, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var defs []BuiltinDef
	if err := yaml.Unmarshal(data, &defs); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %v", path, err)
	}
	return defs, nil
}

// SaveBuiltinRules 把内置规则写入 yaml（首次运行生成可编辑副本）。
func SaveBuiltinRules(path string, defs []BuiltinDef) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(defs)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// MergeDefs 合并规则定义：按 ID 去重，local 优先（便于单机覆盖微调）。
func MergeDefs(local, remote []Def) []Def {
	seen := make(map[string]bool, len(local))
	out := make([]Def, 0, len(local)+len(remote))
	for _, d := range local {
		seen[d.ID] = true
		out = append(out, d)
	}
	for _, d := range remote {
		if !seen[d.ID] {
			out = append(out, d)
		}
	}
	return out
}

// OverrideBuiltinByDefs 用共享/本地自定义规则(defs)按 ID 覆盖内置规则：
// 同 ID 时替换正则/分值/类别；enabled=false 的 Def 不在入参里（Store 已过滤），
// 如需停用内置规则请用 rules_builtin.yaml 的 enabled: false。
func OverrideBuiltinByDefs(builtin []*detector.Rule, defs []Def) []*detector.Rule {
	if len(defs) == 0 {
		return builtin
	}
	byID := make(map[string]Def, len(defs))
	for _, d := range defs {
		byID[d.ID] = d
	}
	out := make([]*detector.Rule, len(builtin))
	for i, r := range builtin {
		if d, ok := byID[r.ID]; ok {
			if rs, err := defsToBuiltinRules([]BuiltinDef{{
				ID: d.ID, Kind: d.Kind, Score: d.Score, Desc: d.Desc,
				Pattern: d.Pattern, Patterns: d.Patterns,
			}}); err == nil && len(rs) == 1 {
				out[i] = rs[0]
				continue
			}
		}
		out[i] = r
	}
	return out
}

// ResolveBuiltinRules 把「代码默认 + 文件覆盖(defs)」合并为最终内置规则集：
// - 文件不存在(defs==nil)：用默认；
// - 文件存在：默认规则中未被文件 ID 提到的保留，被提到的用文件版本替换，
//   enabled=false 的从集合里移除；文件里新增的 ID 追加。
func ResolveBuiltinRules(defs []BuiltinDef, defaults []*detector.Rule) ([]*detector.Rule, error) {
	if defs == nil {
		return defaults, nil
	}
	byID := make(map[string]*detector.Rule, len(defaults))
	order := make([]string, 0, len(defaults))
	for _, r := range defaults {
		byID[r.ID] = r
		order = append(order, r.ID)
	}
	replacements := make(map[string]*detector.Rule)
	for _, d := range defs {
		if d.Enabled != nil && !*d.Enabled {
			delete(byID, d.ID)
			continue
		}
		rs, err := defsToBuiltinRules([]BuiltinDef{d})
		if err != nil {
			return nil, err
		}
		if len(rs) == 0 {
			continue
		}
		if _, exists := byID[d.ID]; !exists {
			order = append(order, d.ID)
		}
		byID[d.ID] = rs[0]
		replacements[d.ID] = rs[0]
	}
	out := make([]*detector.Rule, 0, len(order))
	for _, id := range order {
		if r, ok := byID[id]; ok {
			out = append(out, r)
		}
	}
	return out, nil
}
