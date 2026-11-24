// Package webui 提供内置 Web 可视面板：实时告警、处置记录、隔离区管理。
package webui

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"webshell-guard/internal/action"
	"webshell-guard/internal/aijudge"
	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
	"webshell-guard/internal/notify"
	"webshell-guard/internal/rules"
)

// DirReloader 支持热更新监控目录、触发全量扫描的组件接口。
type DirReloader interface {
	ReconfigureDirs(newDirs []string)
	// ScanNow 触发一次全量扫描；已有扫描在进行时返回 false。
	ScanNow(source string) bool
}

//go:embed static
var staticFS embed.FS

// Server Web UI 服务。
type Server struct {
	cfg       *config.Config
	det       *detector.Detector
	reloader  DirReloader
	judge     *aijudge.Judge
	notifier  *notify.Notifier
	ruleStore *rules.Store
	syncer    *rules.Syncer
	cfgPath   string
	startAt   time.Time
	histPath  string

	mu      sync.Mutex
	clients map[chan action.History]struct{}
}

// New 创建 Web UI 服务。
func New(cfg *config.Config, det *detector.Detector, reloader DirReloader, judge *aijudge.Judge, n *notify.Notifier, rs *rules.Store, syn *rules.Syncer, cfgPath string) *Server {
	return &Server{
		cfg:       cfg,
		det:       det,
		reloader:  reloader,
		judge:     judge,
		notifier:  n,
		ruleStore: rs,
		syncer:    syn,
		cfgPath:   cfgPath,
		startAt:   time.Now(),
		histPath:  filepath.Join(filepath.Dir(cfg.LogFile), "alert_history.jsonl"),
		clients:   map[chan action.History]struct{}{},
	}
}

// Handler 事件回调：推送给所有 SSE 订阅者（非阻塞）。
func (s *Server) Handler() func(action.History) {
	return func(h action.History) {
		s.mu.Lock()
		defer s.mu.Unlock()
		for ch := range s.clients {
			select {
			case ch <- h:
			default: // 慢消费者直接丢弃，不阻塞处置链路
			}
		}
	}
}

// Start 启动 HTTP 服务（阻塞，建议放 goroutine）。
func (s *Server) Start() error {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/data", s.handleData)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/action", s.handleAction)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/rules/test", s.handleRuleTest)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/aiwhitelist", s.handleAIWhitelist)
	mux.HandleFunc("/api/aitest", s.handleAITest)

	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.UI.Port)
	handler := http.Handler(mux)
	if tok := s.cfg.UI.Token; tok != "" {
		handler = basicAuth(handler, tok)
	}
	return http.ListenAndServe(addr, handler)
}

// basicAuth 给整个面板(含静态页与所有 API)加 HTTP Basic 鉴权，防止本机任意进程操作隔离区/规则。
// 用户名任意，密码需等于 token。用 constant-time 比较避免时序侧信道。
func basicAuth(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="webshell-guard", charset="UTF-8"`)
			http.Error(w, "需要面板访问口令(用户名任意, 密码为 ui.token)", http.StatusUnauthorized)
			return
		}
		_ = user
		next.ServeHTTP(w, r)
	})
}

// ---- API: /api/data ----

type dataResp struct {
	Now        string           `json:"now"`
	Uptime     string           `json:"uptime"`
	Action     string           `json:"action"`
	WatchDirs  []string         `json:"watch_dirs"`
	Exts       []string         `json:"extensions"`
	Threshold  int              `json:"threshold"`
	Stats      stats            `json:"stats"`
	Quarantine []quarFile       `json:"quarantine"`
	History    []action.History `json:"history"`
}

type stats struct {
	TotalAlerts int `json:"total_alerts"`
	Quarantined int `json:"quarantined"`
	Deleted     int `json:"deleted"`
	AlertOnly   int `json:"alert_only"`
}

type quarFile struct {
	Name string    `json:"name"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"`
}

func (s *Server) handleData(w http.ResponseWriter, r *http.Request) {
	hist := s.readHistory()
	resp := dataResp{
		Now:       time.Now().Format("2006-01-02 15:04:05"),
		Uptime:    time.Since(s.startAt).Round(time.Second).String(),
		Action:    s.cfg.Action,
		WatchDirs: s.cfg.WatchDirs,
		Exts:      s.cfg.Extensions,
		Threshold: s.cfg.ScoreThreshold,
	}
	for _, h := range hist {
		resp.Stats.TotalAlerts++
		switch h.Action {
		case "quarantine":
			resp.Stats.Quarantined++
		case "delete":
			resp.Stats.Deleted++
		case "alert":
			resp.Stats.AlertOnly++
		}
	}
	// 只返回最近 100 条，倒序
	n := len(hist)
	if n > 100 {
		hist = hist[n-100:]
	}
	for i, j := 0, len(hist)-1; i < j; i, j = i+1, j-1 {
		hist[i], hist[j] = hist[j], hist[i]
	}
	resp.History = hist
	resp.Quarantine = s.listQuarantine()
	writeJSON(w, resp)
}

// listQuarantine 遍历隔离区文件列表。
func (s *Server) listQuarantine() []quarFile {
	var out []quarFile
	root := s.cfg.QuarantineDir
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Name() == action.QuarantineIndexFile {
			return nil // 索引文件不是隔离样本
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		out = append(out, quarFile{Name: filepath.ToSlash(rel), Size: info.Size(), Time: info.ModTime()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// readHistory 读取 JSONL 历史记录。
func (s *Server) readHistory() []action.History {
	data, err := os.ReadFile(s.histPath)
	if err != nil {
		return nil
	}
	var out []action.History
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var h action.History
		if json.Unmarshal([]byte(line), &h) == nil {
			out = append(out, h)
		}
	}
	return out
}

// ---- API: /api/events (SSE) ----

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	ch := make(chan action.History, 16)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprint(w, "retry: 3000\n\n")
	fl.Flush()

	for {
		select {
		case h := <-ch:
			data, _ := json.Marshal(h)
			fmt.Fprintf(w, "data: %s\n\n", data)
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// ---- API: /api/action {op: restore|discard, name: 隔离区相对路径} ----

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Op   string `json:"op"`
		Name string `json:"name"`
		Orig string `json:"orig"` // 手动恢复时指定原路径（历史/索引都查不到时）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	qPath := filepath.Join(s.cfg.QuarantineDir, filepath.FromSlash(req.Name))
	if !strings.HasPrefix(qPath, filepath.Clean(s.cfg.QuarantineDir)) {
		http.Error(w, "非法路径", http.StatusBadRequest)
		return
	}
	switch req.Op {
	case "discard": // 销毁：物理删除隔离文件
		if err := os.Remove(qPath); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"result": "ok"})

	case "restore": // 恢复：按历史/隔离索引放回原路径，查不到时用调用方手填的 orig
		orig := s.findOrig(req.Name)
		if orig == "" {
			orig = strings.TrimSpace(req.Orig)
		}
		if orig == "" {
			http.Error(w, "未找到对应的处置历史，无法确定原路径，请手动填写原文件路径", http.StatusBadRequest)
			return
		}
		if !filepath.IsAbs(orig) {
			http.Error(w, "原路径必须是绝对路径: "+orig, http.StatusBadRequest)
			return
		}
		if _, err := os.Stat(qPath); err != nil {
			http.Error(w, "隔离文件不存在: "+err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := os.Stat(orig); err == nil {
			http.Error(w, "原路径已存在同名文件，为避免覆盖已中止: "+orig, http.StatusBadRequest)
			return
		}
		if err := os.MkdirAll(filepath.Dir(orig), 0o755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, rerr := os.ReadFile(qPath)
		if rerr != nil {
			http.Error(w, "读取隔离文件失败: "+rerr.Error(), http.StatusInternalServerError)
			return
		}
		// 先加白再落地：文件恢复瞬间会触发 fsnotify，若加白晚于事件会被同一规则立刻再隔离
		sha := detector.HashContent(string(data))
		whitelisted := false
		if werr := s.judge.AddWhitelist(orig, sha, "manual-restore"); werr != nil {
			log.Printf("[restore] 加白失败(仍恢复) %s: %v", orig, werr)
		} else {
			whitelisted = true
			log.Printf("[restore] 已加白: %s sha=%s", orig, sha[:12])
		}
		// 同盘 rename，跨盘 copy+delete
		if err := os.Rename(qPath, orig); err != nil {
			if werr := os.WriteFile(orig, data, 0o644); werr != nil {
				http.Error(w, werr.Error(), http.StatusInternalServerError)
				return
			}
			_ = os.Remove(qPath)
		}
		writeJSON(w, map[string]any{"result": "ok", "restored_to": orig, "whitelisted": whitelisted})

	default:
		http.Error(w, "op 只支持 restore|discard", http.StatusBadRequest)
	}
}

// findOrig 找隔离文件的原路径：先查告警历史，再回退到隔离区索引（历史丢失时仍可恢复）。
func (s *Server) findOrig(qRel string) string {
	for _, h := range s.readHistory() {
		if h.NewPath == "" {
			continue
		}
		if s.sameQuarantinePath(h.NewPath, qRel) {
			return h.Orig
		}
	}
	for _, e := range s.readQuarantineIndex() {
		if e.NewPath == "" {
			continue
		}
		if s.sameQuarantinePath(e.NewPath, qRel) {
			return e.Orig
		}
	}
	return ""
}

// sameQuarantinePath 判断历史/索引里记录的隔离路径是否对应当前列表中的相对路径。
func (s *Server) sameQuarantinePath(recorded, qRel string) bool {
	hRel, err := filepath.Rel(s.cfg.QuarantineDir, recorded)
	if err != nil {
		return false
	}
	if filepath.ToSlash(hRel) == qRel {
		return true
	}
	// 兼容旧版本留下的相对路径记录：只比对 文件名 + 相对子目录 的尾部
	return strings.HasSuffix(filepath.ToSlash(recorded), "/"+qRel)
}

// readQuarantineIndex 读取隔离区索引（隔离时写入的 原路径 登记表）。
func (s *Server) readQuarantineIndex() []action.QuarantineIndex {
	data, err := os.ReadFile(filepath.Join(s.cfg.QuarantineDir, action.QuarantineIndexFile))
	if err != nil {
		return nil
	}
	var out []action.QuarantineIndex
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e action.QuarantineIndex
		if json.Unmarshal([]byte(line), &e) == nil && e.Orig != "" {
			out = append(out, e)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

// ---- API: /api/config 设置读写 ----

// settingsOut 返回给前端的当前设置。
type settingsOut struct {
	WatchDirs      []string `json:"watch_dirs"`
	Extensions     []string `json:"extensions"`
	Action         string   `json:"action"`
	ScoreThreshold int      `json:"score_threshold"`
	WebhookURL     string   `json:"webhook_url"`
	WebhookType    string   `json:"webhook_type"`
	DomainWL       []string `json:"external_domain_whitelist"`
	IgnoreDirs     []string `json:"ignore_dirs"`
	CooldownSec    int      `json:"alert_cooldown_sec"`
	CfgPath        string   `json:"cfg_path"`
	// 共享规则同步
	SyncEnabled    bool     `json:"rules_sync_enabled"`
	SyncMode       string   `json:"rules_sync_mode"`
	SyncRepo       string   `json:"rules_sync_repo"`
	SyncFiles      []string `json:"rules_sync_files"`
	SyncBranch     string   `json:"rules_sync_branch"`
	SyncInterval   int      `json:"rules_sync_interval"`
	SyncToken      string   `json:"rules_sync_token"`
	SyncAuthHeader string   `json:"rules_sync_auth_header"`
	// 以下项仅展示，改动需重启
	ScanIntervalSec int `json:"scan_interval_sec"`
	DebounceMS      int `json:"debounce_ms"`
}

// settingsIn 前端提交的设置。
type settingsIn struct {
	WatchDirs      []string `json:"watch_dirs"`
	Extensions     []string `json:"extensions"`
	Action         string   `json:"action"`
	ScoreThreshold int      `json:"score_threshold"`
	WebhookURL     string   `json:"webhook_url"`
	WebhookType    string   `json:"webhook_type"`
	DomainWL       []string `json:"external_domain_whitelist"`
	IgnoreDirs     []string `json:"ignore_dirs"`
	CooldownSec    int      `json:"alert_cooldown_sec"`
	// 共享规则同步
	SyncEnabled    bool     `json:"rules_sync_enabled"`
	SyncMode       string   `json:"rules_sync_mode"`
	SyncRepo       string   `json:"rules_sync_repo"`
	SyncFiles      []string `json:"rules_sync_files"`
	SyncBranch     string   `json:"rules_sync_branch"`
	SyncInterval   int      `json:"rules_sync_interval"`
	SyncToken      string   `json:"rules_sync_token"`
	SyncAuthHeader string   `json:"rules_sync_auth_header"`
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c := s.cfg
		writeJSON(w, settingsOut{
			WatchDirs:       c.WatchDirs,
			Extensions:      c.Extensions,
			Action:          c.Action,
			ScoreThreshold:  c.ScoreThreshold,
			WebhookURL:      c.Webhook.URL,
			WebhookType:     c.Webhook.Type,
			DomainWL:        c.DomainWhitelist,
			IgnoreDirs:      c.IgnoreDirs,
			CooldownSec:     int(c.AlertCooldown.Seconds()),
			CfgPath:         s.cfgPath,
			SyncEnabled:     c.RulesSync.Enabled,
			SyncMode:        c.RulesSync.Mode,
			SyncRepo:        c.RulesSync.Repo,
			SyncFiles:       c.RulesSync.Files,
			SyncBranch:      c.RulesSync.Branch,
			SyncInterval:    c.RulesSync.Interval,
			SyncToken:       c.RulesSync.Token,
			SyncAuthHeader:  c.RulesSync.AuthHeader,
			ScanIntervalSec: int(c.ScanInterval.Seconds()),
			DebounceMS:      int(c.Debounce.Milliseconds()),
		})
	case http.MethodPost:
		var in settingsIn
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "参数解析失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		applied, restart, syncNote, err := s.applySettings(&in)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"result": "ok", "applied_live": applied, "restart_required": restart, "sync_note": syncNote})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// applySettings 校验→即时生效→写回 YAML→尝试立即同步。syncNote 为同步结果说明（可为空）。
func (s *Server) applySettings(in *settingsIn) (applied, restart []string, syncNote string, err error) {
	c := s.cfg

	// ===== 校验 =====
	// watch_dirs 允许为空（先部署后配置），但填了就必须存在。
	cleanDirs := make([]string, 0, len(in.WatchDirs))
	for _, d := range in.WatchDirs {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		abs, aerr := filepath.Abs(d)
		if aerr != nil {
			return nil, nil, "", fmt.Errorf("目录非法 %s: %v", d, aerr)
		}
		if st, serr := os.Stat(abs); serr != nil || !st.IsDir() {
			return nil, nil, "", fmt.Errorf("目录不存在或不是目录: %s", abs)
		}
		cleanDirs = append(cleanDirs, abs)
	}
	if in.Action != "quarantine" && in.Action != "delete" && in.Action != "alert" {
		return nil, nil, "", fmt.Errorf("处置模式只支持 quarantine/delete/alert")
	}
	if in.ScoreThreshold < 1 || in.ScoreThreshold > 100 {
		return nil, nil, "", fmt.Errorf("判恶阈值需在 1-100 之间")
	}
	switch in.WebhookType {
	case "generic", "dingtalk", "feishu", "wecom":
	default:
		return nil, nil, "", fmt.Errorf("webhook 类型只支持 generic/dingtalk/feishu/wecom")
	}
	if in.CooldownSec < 0 || in.CooldownSec > 3600 {
		return nil, nil, "", fmt.Errorf("告警冷却需在 0-3600 秒之间")
	}
	// 共享规则同步校验
	if in.SyncEnabled {
		if in.SyncMode != "raw" && in.SyncMode != "git" {
			return nil, nil, "", fmt.Errorf("共享规则同步模式只支持 raw/git")
		}
		if strings.TrimSpace(in.SyncRepo) == "" {
			return nil, nil, "", fmt.Errorf("启用共享规则同步时必须填写仓库地址")
		}
		if in.SyncInterval != 0 && (in.SyncInterval < 5 || in.SyncInterval > 86400) {
			return nil, nil, "", fmt.Errorf("同步周期需在 5-86400 秒之间")
		}
	}
	normalizeExts := func(exts []string) []string {
		var out []string
		for _, e := range exts {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == "" {
				continue
			}
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			out = append(out, e)
		}
		return out
	}
	in.Extensions = normalizeExts(in.Extensions)

	// ===== 即时生效 =====
	s.reloader.ReconfigureDirs(cleanDirs)
	applied = append(applied, "watch_dirs")

	c.Webhook.URL = strings.TrimSpace(in.WebhookURL)
	s.notifier.SetURL(c.Webhook.URL)
	c.Webhook.Type = in.WebhookType
	s.notifier.SetType(in.WebhookType)
	applied = append(applied, "webhook_url", "webhook_type")

	c.Action = in.Action
	applied = append(applied, "action")

	c.ScoreThreshold = in.ScoreThreshold
	s.det.SetThreshold(in.ScoreThreshold)
	applied = append(applied, "score_threshold")

	c.Extensions = in.Extensions
	applied = append(applied, "extensions")

	c.DomainWhitelist = in.DomainWL
	s.det.SetDomainWhitelist(in.DomainWL)
	applied = append(applied, "external_domain_whitelist")

	c.AlertCooldown = time.Duration(in.CooldownSec) * time.Second
	applied = append(applied, "alert_cooldown")

	c.IgnoreDirs = in.IgnoreDirs // 新扫描生效；已挂监控的旧忽略目录需重启
	applied = append(applied, "ignore_dirs")
	restart = append(restart, "ignore_dirs(部分: 已挂监控的旧目录)", "scan_interval", "debounce", "max_file_size")

	// ===== 共享规则同步：热重配置 =====
	files := make([]string, 0, len(in.SyncFiles))
	for _, f := range in.SyncFiles {
		if f = strings.TrimSpace(f); f != "" {
			files = append(files, f)
		}
	}
	interval := in.SyncInterval
	if interval <= 0 {
		interval = 300
	}
	mode := in.SyncMode
	if !in.SyncEnabled {
		mode = c.RulesSync.Mode // 停用时保留原模式，便于下次开启
	}
	c.RulesSync.Enabled = in.SyncEnabled
	c.RulesSync.Mode = mode
	c.RulesSync.Repo = strings.TrimSpace(in.SyncRepo)
	c.RulesSync.Branch = strings.TrimSpace(in.SyncBranch)
	c.RulesSync.Interval = interval
	c.RulesSync.Token = in.SyncToken
	c.RulesSync.AuthHeader = in.SyncAuthHeader
	c.RulesSync.Files = files
	if s.syncer != nil {
		s.syncer.Reconfigure(rules.RepoConfig{
			Enabled:    in.SyncEnabled,
			Mode:       mode,
			Repo:       c.RulesSync.Repo,
			Branch:     c.RulesSync.Branch,
			Interval:   interval,
			Token:      c.RulesSync.Token,
			AuthHeader: c.RulesSync.AuthHeader,
			Files:      files,
		})
		applied = append(applied, "rules_sync")
		if in.SyncEnabled {
			if serr := s.syncer.SyncNow(); serr != nil {
				syncNote = "配置已保存并生效, 但本次同步失败(缓存规则继续防护): " + serr.Error()
			} else {
				syncNote = fmt.Sprintf("配置已保存并生效, 立即同步成功, 共享规则 %d 条", len(s.syncer.SyncedDefs()))
			}
		} else {
			syncNote = "共享规则同步已停用(已缓存的共享规则不再参与检测)"
		}
	}

	// ===== 写回 YAML（保留注释） =====
	if werr := s.saveYAML(in); werr != nil {
		return applied, restart, syncNote, fmt.Errorf("设置已即时生效, 但写回配置文件失败: %v", werr)
	}
	return applied, restart, syncNote, nil
}

// saveYAML 用 yaml.Node 方式写回，保留原文件注释与结构。
func (s *Server) saveYAML(in *settingsIn) error {
	doc, err := loadYAML(s.cfgPath)
	if err != nil {
		return err
	}
	doc.set("watch_dirs", in.WatchDirs)
	doc.set("extensions", in.Extensions)
	doc.set("action", in.Action)
	doc.set("score_threshold", in.ScoreThreshold)
	doc.set("external_domain_whitelist", in.DomainWL)
	doc.set("ignore_dirs", in.IgnoreDirs)
	doc.set("alert_cooldown", fmt.Sprintf("%ds", in.CooldownSec))
	// webhook 子节点
	wh := doc.get("webhook")
	if wh == nil || wh.Kind != yaml.MappingNode {
		wh = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.set("webhook", wh)
	}
	setChild(wh, "url", in.WebhookURL)
	setChild(wh, "type", in.WebhookType)

	// rules_sync 子节点（applySettings 已把生效值写进 cfg，这里从 cfg 落盘）
	rs := doc.get("rules_sync")
	if rs == nil || rs.Kind != yaml.MappingNode {
		rs = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setChildNode(doc.root, "rules_sync", rs) // 映射节点直插，不能走 encodeNode
	}
	setChild(rs, "enabled", s.cfg.RulesSync.Enabled)
	setChild(rs, "mode", s.cfg.RulesSync.Mode)
	setChild(rs, "repo", s.cfg.RulesSync.Repo)
	setChild(rs, "branch", s.cfg.RulesSync.Branch)
	setChild(rs, "interval", s.cfg.RulesSync.Interval)
	setChild(rs, "token", s.cfg.RulesSync.Token)
	setChild(rs, "auth_header", s.cfg.RulesSync.AuthHeader)
	setChild(rs, "files", s.cfg.RulesSync.Files)

	data, err := yaml.Marshal(doc.root)
	if err != nil {
		return err
	}
	return os.WriteFile(s.cfgPath, data, 0o644)
}

// ---- 极简 yaml.Node 读写工具（保留注释） ----

type yamlDoc struct{ root *yaml.Node }

func loadYAML(path string) (*yamlDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return &yamlDoc{root: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}}, nil
	}
	var n yaml.Node
	if err := yaml.Unmarshal(data, &n); err != nil {
		return nil, err
	}
	root := &n
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		root = n.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		root = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	return &yamlDoc{root: root}, nil
}

// set 设置顶层键值。
func (d *yamlDoc) set(key string, val any) {
	setChild(d.root, key, val)
}

// get 读取顶层键节点。
func (d *yamlDoc) get(key string) *yaml.Node {
	for i := 0; i+1 < len(d.root.Content); i += 2 {
		if d.root.Content[i].Value == key {
			return d.root.Content[i+1]
		}
	}
	return nil
}

func setChild(m *yaml.Node, key string, val any) {
	vn := encodeNode(val)
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = vn
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, vn)
}

// setChildNode 直接插入/替换一个现成的节点（不经过 encodeNode 编码）。
func setChildNode(m *yaml.Node, key string, node *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = node
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, node)
}

func encodeNode(v any) *yaml.Node {
	switch t := v.(type) {
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t}
	case int:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(t)}
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(t)}
	case []string:
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, item := range t {
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: item})
		}
		return seq
	default:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fmt.Sprint(v)}
	}
}

// ---- API: /api/aiwhitelist AI 判定白名单 ----

func (s *Server) handleAIWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items := s.judge.Whitelist()
		if items == nil {
			items = []aijudge.Entry{}
		}
		writeJSON(w, map[string]any{
			"enabled": s.judge.Enabled(),
			"file":    s.judge.WhitelistFile(),
			"items":   items,
		})
	case http.MethodPost:
		var req struct {
			Op  string `json:"op"`
			SHA string `json:"sha"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "参数解析失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Op != "remove" {
			http.Error(w, "op 只支持 remove", http.StatusBadRequest)
			return
		}
		if err := s.judge.RemoveWhitelist(req.SHA); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"result": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- API: /api/aitest AI 接口连通性测试 ----

func (s *Server) handleAITest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var ov aijudge.SignOverride
	_ = json.NewDecoder(r.Body).Decode(&ov) // body 可为空：沿用配置文件里的签名方式
	res, err := s.judge.Test(r.Context(), &ov)
	// 诊断接口统一 200 + ok 字段，方便前端直接展示原始回答与耗时
	out := map[string]any{
		"ok":         err == nil,
		"url":        res.URL,
		"answer":     res.Answer,
		"raw":        res.Raw,
		"status":     res.Status,
		"date":       res.Date,
		"key":        res.Key,
		"verdict":    string(res.Verdict),
		"elapsed_ms": res.ElapsedMS,
	}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, out)
}

// ---- API: /api/rules 规则库管理 ----

func (s *Server) applyRulesToDetector() {
	// 与 main 一致：本地/共享规则按 ID 覆盖内置 + 作为追加规则注入。
	localDefs := s.ruleStore.List()
	var syncedDefs []rules.Def
	var syncedRules []*detector.Rule
	if s.syncer != nil {
		syncedDefs = s.syncer.SyncedDefs()
		syncedRules = s.syncer.DetectorRules()
	}
	allDefs := rules.MergeDefs(localDefs, syncedDefs)
	base := s.det.BuiltinBaseRules()
	s.det.SetBuiltinOverrides(base, rules.OverrideBuiltinByDefs(base, allDefs))
	s.det.SetCustomRules(rules.MergeRules(s.ruleStore.DetectorRules(), syncedRules))
}

// rescanAsync 规则热更新后异步补一次全量扫描：规则只对"之后的检测"生效，
// 已经躺在目录里的旧文件不会自己产生写入事件，不补扫就得等周期扫描或重启。
func (s *Server) rescanAsync(reason string) {
	if s.reloader == nil {
		return
	}
	go func() {
		if s.reloader.ScanNow(reason) {
			log.Printf("[scan] 规则变更后已触发全量复检(%s)", reason)
		}
	}()
}

// handleScan 手动触发一次全量扫描：POST /api/scan
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.reloader == nil {
		http.Error(w, "扫描器未就绪", http.StatusServiceUnavailable)
		return
	}
	go func() {
		s.reloader.ScanNow("manual")
	}()
	writeJSON(w, map[string]any{"result": "ok", "msg": "已开始全量扫描，命中结果会进入告警流与处置记录"})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resp := map[string]any{
			"builtin":    detector.BuiltinRuleInfos(),
			"custom":     s.ruleStore.List(),
			"rules_file": s.ruleStore.Path(),
		}
		if s.syncer != nil && s.cfg.RulesSync.Enabled {
			resp["synced"] = s.syncer.SyncedDefs()
			resp["sync_status"] = s.syncer.Status()
		} else {
			resp["synced"] = []rules.Def{}
			resp["sync_status"] = nil
		}
		writeJSON(w, resp)
	case http.MethodPost:
		var req struct {
			Op    string      `json:"op"`
			ID    string      `json:"id"`
			On    *bool       `json:"on"`
			Rule  *rules.Def  `json:"rule"`
			Rules []rules.Def `json:"rules"`
			Raw   string      `json:"raw"` // 原始文本规则(JSON/YAML)，优先级高于 Rules
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "参数解析失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		switch req.Op {
		case "add":
			if req.Rule == nil {
				http.Error(w, "缺少 rule", http.StatusBadRequest)
				return
			}
			d, err := s.ruleStore.Add(*req.Rule)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.applyRulesToDetector()
			s.rescanAsync("rule-add")
			writeJSON(w, map[string]any{"result": "ok", "rule": d, "live": "规则已热生效，并已触发全量复检"})
		case "update":
			if req.Rule == nil {
				http.Error(w, "缺少 rule", http.StatusBadRequest)
				return
			}
			// 兼容只传 rule.id 的调用方
			id := req.ID
			if id == "" {
				id = req.Rule.ID
			}
			if id == "" {
				http.Error(w, "缺少规则 ID", http.StatusBadRequest)
				return
			}
			if err := s.ruleStore.Update(id, *req.Rule); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.applyRulesToDetector()
			s.rescanAsync("rule-update")
			writeJSON(w, map[string]any{"result": "ok", "live": "规则已热生效，并已触发全量复检"})
		case "delete":
			if err := s.ruleStore.Delete(req.ID); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.applyRulesToDetector()
			writeJSON(w, map[string]any{"result": "ok", "live": "规则已移除并热生效"})
		case "toggle":
			if req.On == nil {
				http.Error(w, "缺少 on", http.StatusBadRequest)
				return
			}
			if err := s.ruleStore.SetEnabled(req.ID, *req.On); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.applyRulesToDetector()
			s.rescanAsync("rule-toggle")
			writeJSON(w, map[string]any{"result": "ok", "live": "启停状态已热生效，并已触发全量复检"})
		case "import":
			defs := req.Rules
			if raw := strings.TrimSpace(req.Raw); raw != "" {
				parsed, perr := parseRulesText(raw)
				if perr != nil {
					http.Error(w, perr.Error(), http.StatusBadRequest)
					return
				}
				defs = parsed
			}
			if len(defs) == 0 {
				http.Error(w, "没有可导入的规则", http.StatusBadRequest)
				return
			}
			n, skipped := s.ruleStore.Import(defs)
			s.applyRulesToDetector()
			s.rescanAsync("rule-import")
			writeJSON(w, map[string]any{"result": "ok", "imported": n, "skipped": skipped, "live": "导入规则已热生效，并已触发全量复检"})
		case "sync":
			if s.syncer == nil || !s.cfg.RulesSync.Enabled {
				http.Error(w, "规则同步未启用(配置 rules_sync.enabled=true)", http.StatusBadRequest)
				return
			}
			if err := s.syncer.SyncNow(); err != nil {
				http.Error(w, "同步失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{"result": "ok", "status": s.syncer.Status()})
		default:
			http.Error(w, "op 只支持 add|update|delete|toggle|import|sync", http.StatusBadRequest)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// parseRulesText 解析用户粘贴/上传的规则文本：兼容 JSON 与 YAML、数组与单条对象。
func parseRulesText(raw string) ([]rules.Def, error) {
	var list []rules.Def
	if err := yaml.Unmarshal([]byte(raw), &list); err == nil && len(list) > 0 {
		return list, nil
	}
	var one rules.Def
	if err := yaml.Unmarshal([]byte(raw), &one); err == nil && one.Kind != "" && (one.Pattern != "" || len(one.Patterns) > 0) {
		return []rules.Def{one}, nil
	}
	return nil, fmt.Errorf("无法识别规则格式：支持 JSON/YAML 数组或单条对象(需含 kind 与 pattern/patterns)")
}

// handleRuleTest 在线样本测试：用当前全部规则(内置+自定义)检测粘贴的内容。
func (s *Server) handleRuleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "参数解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		http.Error(w, "样本内容为空", http.StatusBadRequest)
		return
	}
	res := s.det.Detect(req.Content, int64(len(req.Content)))
	writeJSON(w, map[string]any{
		"score":        res.Score,
		"clean":        res.Clean,
		"hits":         res.Hits,
		"would_action": res.Score >= s.cfg.ScoreThreshold,
	})
}
