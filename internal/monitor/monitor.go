// Package monitor 实现 fsnotify 实时监控与周期全量扫描。
package monitor

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"webshell-guard/internal/action"
	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
)

// Engine 监控引擎。
type Engine struct {
	cfg      *config.Config
	det      *detector.Detector
	exec     *action.Executor
	baseline *detector.Baseline
	watcher  *fsnotify.Watcher

	mu       sync.Mutex
	pending  map[string]*time.Timer // 防抖定时器
	lastScan time.Time
}

// New 创建监控引擎。
func New(cfg *config.Config, det *detector.Detector, exec *action.Executor, baseline *detector.Baseline) (*Engine, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Engine{
		cfg:      cfg,
		det:      det,
		exec:     exec,
		baseline: baseline,
		watcher:  w,
		pending:  map[string]*time.Timer{},
	}, nil
}

// Run 启动监控（阻塞），watchCh 上返回告警事件，errCh 上返回致命错误。
func (e *Engine) Run(watchCh chan<- string, errCh chan<- error) {
	// 递归添加所有 watch 目录
	for _, root := range e.cfg.WatchDirs {
		if err := e.addRecursive(root); err != nil {
			errCh <- err
			return
		}
		log.Printf("[monitor] 已开始监控: %s", root)
	}

	go e.scanLoop(watchCh)

	for {
		select {
		case ev, ok := <-e.watcher.Events:
			if !ok {
				return
			}
			e.handleEvent(ev, watchCh)
		case err, ok := <-e.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[monitor] watcher 错误: %v", err)
		}
	}
}

// Close 释放资源。
func (e *Engine) Close() {
	e.watcher.Close()
}

// ReconfigureDirs 热更新监控目录：新增目录递归挂监控，删掉的目录取消监控。
func (e *Engine) ReconfigureDirs(newDirs []string) {
	e.mu.Lock()
	old := e.cfg.WatchDirs
	e.cfg.WatchDirs = newDirs
	e.mu.Unlock()

	oldRoots := map[string]bool{}
	for _, d := range old {
		oldRoots[strings.ToLower(filepath.Clean(d))] = true
	}
	// 取消已不在新目录列表下的监控
	for _, p := range e.watcher.WatchList() {
		under := false
		for _, nd := range newDirs {
			rel, err := filepath.Rel(filepath.Clean(nd), p)
			if err == nil && !strings.HasPrefix(rel, "..") {
				under = true
				break
			}
		}
		if !under {
			_ = e.watcher.Remove(p)
		}
	}
	// 新目录递归挂监控
	for _, nd := range newDirs {
		if !oldRoots[strings.ToLower(filepath.Clean(nd))] {
			if err := e.addRecursive(nd); err != nil {
				log.Printf("[monitor] 热更新目录失败 %s: %v", nd, err)
			} else {
				log.Printf("[monitor] 热更新: 新增监控 %s", nd)
			}
		}
	}
	log.Printf("[monitor] 监控目录已更新: %v", newDirs)
}

// addRecursive 递归添加目录到 watcher。
func (e *Engine) addRecursive(root string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 单个条目失败不中断
		}
		if d.IsDir() {
			if e.cfg.IsIgnoredDir(p) && !equalFoldPath(p, root) {
				log.Printf("[monitor] 忽略目录: %s", p)
				return filepath.SkipDir
			}
			if err := e.watcher.Add(p); err != nil {
				log.Printf("[monitor] 添加监控失败 %s: %v", p, err)
			}
		}
		return nil
	})
}

func equalFoldPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// handleEvent 处理单个 fsnotify 事件。
func (e *Engine) handleEvent(ev fsnotify.Event, watchCh chan<- string) {
	// 新目录 → 递归加入监控
	if ev.Op&fsnotify.Create == fsnotify.Create {
		if st, err := os.Stat(ev.Name); err == nil && st.IsDir() {
			if !e.cfg.IsIgnoredDir(ev.Name) {
				_ = e.addRecursive(ev.Name)
			}
			return
		}
	}
	if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) == 0 {
		return
	}
	if !e.cfg.IsWatchedExt(ev.Name) || e.cfg.IsIgnoredDir(ev.Name) {
		return
	}
	e.schedule(ev.Name, watchCh)
}

// schedule 防抖调度：debounce 时间内无新写入才真正检测。
func (e *Engine) schedule(path string, watchCh chan<- string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if t, ok := e.pending[path]; ok {
		t.Reset(e.cfg.Debounce)
		return
	}
	e.pending[path] = time.AfterFunc(e.cfg.Debounce, func() {
		e.mu.Lock()
		delete(e.pending, path)
		e.mu.Unlock()
		e.checkFile(path, "realtime", watchCh)
	})
}

// checkFile 检测单个文件并按需处置。
func (e *Engine) checkFile(path, source string, watchCh chan<- string) {
	st, err := os.Stat(path)
	if err != nil {
		return // 文件可能已被删除
	}
	if st.IsDir() || st.Size() > e.cfg.MaxFileSize {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	res := e.det.Detect(string(data), st.Size())
	inBase, _ := e.baseline.IsBaseline(path, res.SHA256)

	// 判定条件：评分达标，或（在基线中但内容被改且命中任何规则）
	if res.Clean || res.Score < e.det.Threshold() {
		// 干净文件：更新基线（增量学习）
		if res.Clean && e.cfg.Baseline.Enabled {
			_ = e.baseline.Update(path, res.SHA256)
		}
		return
	}

	log.Printf("[detect] 发现可疑文件(%s): %s score=%d baseline=%v",
		source, path, res.Score, inBase)
	select {
	case watchCh <- path:
	default:
	}
	if _, err := e.exec.Handle(path, res, inBase); err != nil {
		log.Printf("[detect] 处置失败 %s: %v", path, err)
	}
}

// scanLoop 周期全量兜底扫描。
func (e *Engine) scanLoop(watchCh chan<- string) {
	// 启动时先扫一遍
	e.fullScan("startup", watchCh)
	t := time.NewTicker(e.cfg.ScanInterval)
	defer t.Stop()
	for range t.C {
		e.fullScan("periodic", watchCh)
	}
}

// fullScan 全量扫描所有监控目录。
func (e *Engine) fullScan(source string, watchCh chan<- string) {
	start := time.Now()
	count := 0
	for _, root := range e.cfg.WatchDirs {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if e.cfg.IsIgnoredDir(p) && !equalFoldPath(p, root) {
					return filepath.SkipDir
				}
				return nil
			}
			if e.cfg.IsWatchedExt(p) {
				count++
				e.checkFile(p, source, watchCh)
			}
			return nil
		})
	}
	log.Printf("[scan] %s 全量扫描完成: %d 个文件, 耗时 %s", source, count, time.Since(start))
}
