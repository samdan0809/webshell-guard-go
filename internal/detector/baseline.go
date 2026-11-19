package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Baseline 文件哈希基线。
type Baseline struct {
	mu    sync.RWMutex
	path  string
	items map[string]string // 相对路径 -> sha256
}

// baselineFile 磁盘格式。
type baselineFile struct {
	Items map[string]string `json:"items"`
}

// NewBaseline 加载基线文件（不存在则空基线）。
func NewBaseline(path string) *Baseline {
	b := &Baseline{path: path, items: map[string]string{}}
	if data, err := os.ReadFile(path); err == nil {
		var bf baselineFile
		if json.Unmarshal(data, &bf) == nil && bf.Items != nil {
			b.items = bf.Items
		}
	}
	return b
}

// IsBaseline 判断文件（绝对路径）是否在基线中，返回是否在基线及基线哈希是否与当前一致。
func (b *Baseline) IsBaseline(absPath, curHash string) (inBaseline, unchanged bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	h, ok := b.items[filepath.ToSlash(absPath)]
	return ok, ok && h == curHash
}

// Update 更新某文件基线并落盘。
func (b *Baseline) Update(absPath, hash string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items[filepath.ToSlash(absPath)] = hash
	return b.save()
}

// Remove 删除某文件基线并落盘。
func (b *Baseline) Remove(absPath string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.items, filepath.ToSlash(absPath))
	return b.save()
}

// Count 基线条目数。
func (b *Baseline) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.items)
}

func (b *Baseline) save() error {
	if dir := filepath.Dir(b.path); dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	data, err := json.MarshalIndent(baselineFile{Items: b.items}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(b.path, data, 0o644)
}

// BuildAll 全量重建基线（工具性接口，供手工维护）。
func (b *Baseline) BuildAll(pairs map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = pairs
	return b.save()
}
