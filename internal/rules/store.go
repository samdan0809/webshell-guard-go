// Package rules 实现自定义特征规则库：持久化、校验、导入、热加载。
//
// 规则存储在 config.yaml 同目录的 rules_custom.yaml 中，独立于主配置，
// 便于单独更新特征库（覆盖该文件或通过面板/API 导入均可）。
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"webshell-guard/internal/detector"
)

// Def 单条自定义规则定义（可序列化为 yaml/json）。
type Def struct {
	ID       string   `yaml:"id" json:"id"`
	Kind     string   `yaml:"kind" json:"kind"` // webshell | horse
	Score    int      `yaml:"score" json:"score"`
	Desc     string   `yaml:"desc" json:"desc"`
	Pattern  string   `yaml:"pattern,omitempty" json:"pattern"`            // 单正则
	Patterns []string `yaml:"patterns,omitempty" json:"patterns,omitempty"` // 组合规则：全部命中才计分
	Keywords []string `yaml:"keywords,omitempty" json:"keywords,omitempty"` // 关键字组合：全部出现才计分(普通文本,自动转义)
	Enabled  bool     `yaml:"enabled" json:"enabled"`
	Source   string   `yaml:"source,omitempty" json:"source,omitempty"` // manual | import
	Created  string   `yaml:"created,omitempty" json:"created,omitempty"`
}

// Store 自定义规则库。
type Store struct {
	mu   sync.Mutex
	path string
	defs []Def
}

// New 创建规则库并从 path 加载（文件不存在则视为空库）。
func New(path string) *Store {
	s := &Store{path: path}
	s.load()
	return s
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return
	}
	var defs []Def
	if yaml.Unmarshal(data, &defs) == nil {
		// 过滤非法正则，保证检测器安全
		out := make([]Def, 0, len(defs))
		for _, d := range defs {
			if d.validate() == nil {
				out = append(out, d)
			}
		}
		s.defs = out
	}
}

// validate 校验单条规则；返回错误信息（含原因）。
func (d *Def) validate() error {
	if strings.TrimSpace(d.Desc) == "" {
		return fmt.Errorf("规则描述不能为空")
	}
	if d.Score < 1 || d.Score > 100 {
		return fmt.Errorf("分值需在 1-100 之间")
	}
	if d.Kind != "webshell" && d.Kind != "horse" {
		return fmt.Errorf("类别只支持 webshell/horse")
	}
	modes := 0
	if d.Pattern != "" {
		modes++
	}
	if len(d.Patterns) > 0 {
		modes++
	}
	if len(d.Keywords) > 0 {
		modes++
	}
	if modes == 0 {
		return fmt.Errorf("至少提供一种检测方式(pattern / patterns / keywords)")
	}
	if modes > 1 {
		return fmt.Errorf("pattern、patterns、keywords 只能选一种")
	}
	if d.Pattern != "" {
		if _, err := regexp.Compile("(?i)" + d.Pattern); err != nil {
			return fmt.Errorf("正则非法: %v", err)
		}
	}
	for i, p := range d.Patterns {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("组合正则第 %d 条为空", i+1)
		}
		if _, err := regexp.Compile("(?i)" + p); err != nil {
			return fmt.Errorf("组合正则第 %d 条非法: %v", i+1, err)
		}
	}
	kw := 0
	for i, k := range d.Keywords {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("关键字第 %d 条为空", i+1)
		}
		if len(k) > 200 {
			return fmt.Errorf("关键字第 %d 条过长(上限 200 字符)", i+1)
		}
		kw++
	}
	if kw == 1 {
		return fmt.Errorf("关键字组合至少需要 2 条(单关键字请用 pattern)")
	}
	return nil
}

// List 返回全部规则副本。
func (s *Store) List() []Def {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Def, len(s.defs))
	copy(out, s.defs)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Path 返回规则文件路径。
func (s *Store) Path() string { return s.path }

// Count 返回启用中的规则数。
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, d := range s.defs {
		if d.Enabled {
			n++
		}
	}
	return n
}

// Add 新增规则。ID 留空则自动生成；返回最终规则。
func (s *Store) Add(d Def) (Def, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := d.validate(); err != nil {
		return d, err
	}
	if strings.TrimSpace(d.ID) == "" {
		d.ID = genID(d)
	} else {
		d.ID = strings.ToUpper(strings.TrimSpace(d.ID))
		for _, e := range s.defs {
			if e.ID == d.ID {
				return d, fmt.Errorf("规则 ID 已存在: %s", d.ID)
			}
		}
	}
	// 相同正则防重复
	for _, e := range s.defs {
		if sameRegex(e, d) {
			return d, fmt.Errorf("相同正则的规则已存在: %s(%s)", e.ID, e.Desc)
		}
	}
	d.Enabled = true
	if d.Source == "" {
		d.Source = "manual"
	}
	if d.Created == "" {
		d.Created = time.Now().Format("2006-01-02 15:04:05")
	}
	s.defs = append(s.defs, d)
	if err := s.save(); err != nil {
		s.defs = s.defs[:len(s.defs)-1] // 回滚
		return d, err
	}
	return d, nil
}

// Update 按 ID 覆盖更新。
func (s *Store) Update(id string, d Def) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d.ID = strings.ToUpper(strings.TrimSpace(id))
	if err := d.validate(); err != nil {
		return err
	}
	idx := -1
	for i := range s.defs {
		if s.defs[i].ID == d.ID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("规则不存在: %s", d.ID)
	}
	old := s.defs[idx]
	d.Enabled = old.Enabled
	d.Created = old.Created
	if d.Source == "" {
		d.Source = old.Source
	}
	s.defs[idx] = d
	if err := s.save(); err != nil {
		s.defs[idx] = old
		return err
	}
	return nil
}

// Delete 删除规则。
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.defs {
		if s.defs[i].ID == id {
			old := s.defs[i]
			s.defs = append(s.defs[:i], s.defs[i+1:]...)
			if err := s.save(); err != nil {
				s.defs = append(s.defs[:i], append([]Def{old}, s.defs[i:]...)...)
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("规则不存在: %s", id)
}

// SetEnabled 启用/停用规则。
func (s *Store) SetEnabled(id string, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.defs {
		if s.defs[i].ID == id {
			old := s.defs[i].Enabled
			s.defs[i].Enabled = on
			if err := s.save(); err != nil {
				s.defs[i].Enabled = old
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("规则不存在: %s", id)
}

// Import 批量导入规则（按 ID / 相同正则去重跳过）。返回 (导入数, 跳过详情)。
func (s *Store) Import(defs []Def) (int, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	var skipped []string
	for _, d := range defs {
		if err := d.validate(); err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", orName(d), err))
			continue
		}
		if strings.TrimSpace(d.ID) == "" {
			d.ID = genID(d)
		} else {
			d.ID = strings.ToUpper(strings.TrimSpace(d.ID))
		}
		dup := false
		for _, e := range s.defs {
			if e.ID == d.ID || sameRegex(e, d) {
				skipped = append(skipped, fmt.Sprintf("%s: 已存在(%s)", orName(d), e.ID))
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		d.Enabled = true
		d.Source = "import"
		if d.Created == "" {
			d.Created = time.Now().Format("2006-01-02 15:04:05")
		}
		s.defs = append(s.defs, d)
		n++
	}
	if n > 0 {
		if err := s.save(); err != nil {
			return 0, append(skipped, "保存失败: "+err.Error())
		}
	}
	return n, skipped
}

func orName(d Def) string {
	if d.ID != "" {
		return d.ID
	}
	return d.Desc
}

func sameRegex(a, b Def) bool {
	if a.Pattern != "" && a.Pattern == b.Pattern {
		return true
	}
	if len(a.Patterns) > 0 && len(b.Patterns) > 0 && strings.Join(a.Patterns, "\x00") == strings.Join(b.Patterns, "\x00") {
		return true
	}
	if len(a.Keywords) > 0 && len(b.Keywords) > 0 && strings.Join(a.Keywords, "\x00") == strings.Join(b.Keywords, "\x00") {
		return true
	}
	return false
}

func genID(d Def) string {
	sum := sha256.Sum256([]byte(d.Pattern + strings.Join(d.Patterns, "\x00") + strings.Join(d.Keywords, "\x00") + d.Desc))
	return "CR-" + strings.ToUpper(hex.EncodeToString(sum[:4]))
}

// ToDetectorRules 把规则定义转换为检测器规则（跳过停用的）。
func ToDetectorRules(defs []Def) []*detector.Rule {
	var out []*detector.Rule
	for _, d := range defs {
		if !d.Enabled {
			continue
		}
		r := &detector.Rule{ID: d.ID, Score: d.Score, Desc: d.Desc}
		if d.Kind == "horse" {
			r.Kind = detector.KindHorse
		} else {
			r.Kind = detector.KindWebshell
		}
		switch {
		case d.Pattern != "":
			r.Pattern = regexp.MustCompile("(?i)" + d.Pattern) // validate 已保证可编译
		case len(d.Keywords) > 0:
			// 关键字按纯文本匹配：全部出现才计分，正则元字符自动转义。
			r.Combination = true
			for _, k := range d.Keywords {
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				r.PatternAll = append(r.PatternAll, regexp.MustCompile("(?i)"+regexp.QuoteMeta(k)))
			}
		default:
			r.Combination = true
			for _, p := range d.Patterns {
				r.PatternAll = append(r.PatternAll, regexp.MustCompile("(?i)"+p))
			}
		}
		out = append(out, r)
	}
	return out
}

// DetectorRules 转换为检测器规则列表（仅启用的）。
func (s *Store) DetectorRules() []*detector.Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ToDetectorRules(s.defs)
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(s.defs)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}
