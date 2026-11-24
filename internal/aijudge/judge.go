// Package aijudge 通过外部 AI 接口复核"含风险字符"的脚本是否为恶意代码，
// 并把判定安全的文件按 SHA256 永久加白（文件内容一变哈希就变，会重新检测）。
package aijudge

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AI 固定回答词汇：SAFE / MALICIOUS。
const (
	TokenSafe      = "SAFE"
	TokenMalicious = "MALICIOUS"
)

// DefaultKeywords 触发 AI 复核的风险字符（正则，忽略大小写）。
var DefaultKeywords = []string{
	`ProcessStartInfo`,
	`Process`,
	`.WriteAllText`,
	`.WriteAllBytes`,
	`FromBase64String`,
	`GetEnvironmentVariable`,
	`comspec`,
	`powershell`,
	`cmd.exe`,
	`Process`,
}

// Config AI 复核配置。
type Config struct {
	Enabled bool
	// Type 接口类型：chat(自建 chat.ashx，MD5 签名+表单，默认) | openai(OpenAI 兼容，Bearer key)。
	Type   string
	URL    string
	AppKey string
	// Model openai 模式必填：gpt-4o-mini / deepseek-chat 等。
	Model         string
	Timeout       time.Duration
	Keywords      []string
	WhitelistFile string
	// MaxSnippet 送审代码片段的最大字节数。
	MaxSnippet int
	// DateUnit 时间戳形式（仅 chat 模式）：s(秒) | ms(毫秒,默认) | datetime(yyyyMMddHHmmss)。
	DateUnit string
	// KeyOrder key 拼接顺序（仅 chat 模式）：date_first(时间戳+APPKEY,默认) | appkey_first(APPKEY+时间戳)。
	KeyOrder string
	// KeyUpper MD5 是否转大写（仅 chat 模式）。
	KeyUpper bool
}

// SignOverride 签名参数临时覆盖（连通性测试时用于逐项试接口文档要求）。
type SignOverride struct {
	DateUnit string `json:"date_unit"`
	KeyOrder string `json:"key_order"`
	KeyUpper *bool  `json:"key_upper"`
}

// Verdict AI 裁定结果。
type Verdict string

const (
	Safe      Verdict = "safe"
	Malicious Verdict = "malicious"
	Unknown   Verdict = "unknown"
)

// Entry 白名单条目。
type Entry struct {
	SHA256 string `json:"sha256"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Time   string `json:"time"`
}

type whitelistFile struct {
	Items []Entry `json:"items"`
}

// Judge AI 判定器（含白名单持久化与按哈希的结果缓存）。
type Judge struct {
	cfg    Config
	client *http.Client
	risk   *regexp.Regexp

	mu      sync.Mutex
	entries map[string]Entry   // sha256 -> entry
	cache   map[string]Verdict // sha256 -> verdict（同一次运行内不重复请求）
}

// New 创建判定器。Enabled=false 时也可安全调用（不会发请求），便于上层统一处理。
func New(cfg Config) (*Judge, error) {
	cfg.URL = strings.TrimSpace(cfg.URL)
	cfg.AppKey = strings.TrimSpace(cfg.AppKey)
	cfg.Model = strings.TrimSpace(cfg.Model)
	switch cfg.Type {
	case "", "chat":
		cfg.Type = "chat"
		if cfg.AppKey == "" {
			cfg.AppKey = "dang888" // 默认 APPKEY，可在 config.yaml 覆盖
		}
	case "openai":
		if cfg.Model == "" {
			return nil, errors.New("ai_judge.type=openai 时必须配置 ai_judge.model")
		}
	default:
		return nil, fmt.Errorf("ai_judge.type 只支持 chat|openai, 当前 %q", cfg.Type)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	if cfg.MaxSnippet <= 0 {
		cfg.MaxSnippet = 1500
	}
	switch cfg.DateUnit {
	case "ms", "datetime", "s":
	default:
		cfg.DateUnit = "ms" // 该接口的 date 是毫秒时间戳
	}
	if cfg.KeyOrder != "appkey_first" {
		cfg.KeyOrder = "date_first"
	}
	if cfg.Enabled && cfg.URL == "" {
		return nil, errors.New("ai_judge.url 未配置")
	}
	keywords := cfg.Keywords
	if len(keywords) == 0 {
		keywords = DefaultKeywords
	}
	parts := make([]string, 0, len(keywords))
	for _, k := range keywords {
		if k = strings.TrimSpace(k); k != "" {
			parts = append(parts, "(?i:"+k+")")
		}
	}
	risk, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		return nil, fmt.Errorf("ai_judge.keywords 正则非法: %w", err)
	}
	j := &Judge{
		cfg:     cfg,
		client:  &http.Client{Timeout: cfg.Timeout},
		risk:    risk,
		entries: map[string]Entry{},
		cache:   map[string]Verdict{},
	}
	j.load()
	return j, nil
}

// Enabled 是否启用。
func (j *Judge) Enabled() bool { return j != nil && j.cfg.Enabled }

// HasRisk 内容是否命中风险字符。
func (j *Judge) HasRisk(content string) bool {
	return j != nil && j.cfg.Enabled && j.risk != nil && j.risk.MatchString(content)
}

// IsWhitelisted 该内容哈希是否已在白名单（AI 曾判定安全）。
func (j *Judge) IsWhitelisted(sha string) bool {
	if j == nil || sha == "" {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_, ok := j.entries[strings.ToLower(sha)]
	return ok
}

// Whitelist 返回全部白名单条目（按时间倒序）。
func (j *Judge) Whitelist() []Entry {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Entry, 0, len(j.entries))
	for _, e := range j.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Time > out[b].Time })
	return out
}

// WhitelistFile 白名单文件路径。
func (j *Judge) WhitelistFile() string {
	if j == nil {
		return ""
	}
	return j.cfg.WhitelistFile
}

// AddWhitelist 手动加白（人工恢复文件后使用），reason 用于区分来源（ai-safe / manual-restore）。
func (j *Judge) AddWhitelist(path, sha, reason string) error {
	if j == nil {
		return errors.New("白名单未初始化")
	}
	sha = strings.ToLower(strings.TrimSpace(sha))
	if sha == "" {
		return errors.New("文件哈希为空，无法加白")
	}
	if reason == "" {
		reason = "manual"
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries[sha] = Entry{
		SHA256: sha,
		Path:   path,
		Reason: reason,
		Time:   time.Now().Format("2006-01-02 15:04:05"),
	}
	return j.saveLocked()
}

// RemoveWhitelist 移出一条白名单记录。
func (j *Judge) RemoveWhitelist(sha string) error {
	if j == nil {
		return errors.New("AI 判定未启用")
	}
	sha = strings.ToLower(strings.TrimSpace(sha))
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.entries[sha]; !ok {
		return fmt.Errorf("白名单不存在: %s", sha)
	}
	delete(j.entries, sha)
	return j.saveLocked()
}

// Review 请求 AI 判定。path/content 仅用于构造提示词，sha 用于缓存与加白。
// 判定 SAFE 时自动写入+持久化白名单，返回 Safe。
func (j *Judge) Review(ctx context.Context, path, content, sha string) (Verdict, error) {
	if j == nil || !j.cfg.Enabled {
		return Unknown, errors.New("AI 判定未启用")
	}
	sha = strings.ToLower(strings.TrimSpace(sha))
	j.mu.Lock()
	if v, ok := j.cache[sha]; ok {
		j.mu.Unlock()
		return v, nil
	}
	j.mu.Unlock()

	resp, err := j.ask(ctx, promptCriteria(), promptTarget(path, content, j.cfg.MaxSnippet), nil)
	if err != nil {
		return Unknown, err
	}
	answer := resp.Answer
	v, err := parseVerdict(answer)
	if err != nil {
		return Unknown, fmt.Errorf("%w (原始回答: %s)", err, truncateRunes(answer, 120))
	}

	j.mu.Lock()
	j.cache[sha] = v
	if v == Safe {
		j.entries[sha] = Entry{
			SHA256: sha,
			Path:   path,
			Reason: "ai-safe",
			Time:   time.Now().Format("2006-01-02 15:04:05"),
		}
		if serr := j.saveLocked(); serr != nil {
			j.mu.Unlock()
			return v, fmt.Errorf("判定安全但白名单落盘失败: %w", serr)
		}
	}
	j.mu.Unlock()
	return v, nil
}

// TestResult 接口连通性测试结果。
type TestResult struct {
	OK        bool    `json:"ok"`
	URL       string  `json:"url"`
	Answer    string  `json:"answer"` // 从响应里提取的回答
	Raw       string  `json:"raw"`    // 响应原文（截断），接口报"权限不足"这类错误时靠它定位
	Status    int     `json:"status"` // HTTP 状态码
	Date      string  `json:"date"`   // 本次发送的 date 参数
	Key       string  `json:"key"`    // 本次发送的 key 参数（md5，可对照接口文档核对）
	Verdict   Verdict `json:"verdict"`
	ElapsedMS int64   `json:"elapsed_ms"`
}

// TestPrompt 连通性测试用的提示词（回答 SAFE 即视为接口可用）。
const TestPrompt = "这是一次接口连通性测试。请严格只回复一个词：SAFE"

// Test 发一次探测请求，验证地址/签名/返回格式是否正常（不影响缓存与白名单）。
// ov 非 nil 时可临时覆盖签名方式，便于按接口文档逐项排查。
func (j *Judge) Test(ctx context.Context, ov *SignOverride) (TestResult, error) {
	if j == nil || !j.cfg.Enabled {
		return TestResult{}, errors.New("AI 复核未启用（请配置 ai_judge.enabled 后重启）")
	}
	res := TestResult{URL: j.cfg.URL}
	start := time.Now()
	resp, err := j.ask(ctx, TestPrompt, "", ov)
	res.ElapsedMS = time.Since(start).Milliseconds()
	res.Answer = truncateRunes(resp.Answer, 300)
	res.Raw = truncateRunes(resp.Raw, 500)
	res.Status = resp.Status
	res.Date = resp.Date
	res.Key = resp.Key
	if err != nil {
		return res, err
	}
	v, perr := parseVerdict(resp.Answer)
	res.Verdict = v
	res.OK = perr == nil
	if perr != nil {
		return res, fmt.Errorf("接口可达，但回答不是固定词汇: %w", perr)
	}
	return res, nil
}

// askResponse 一次请求的原始返回。
type askResponse struct {
	Answer string
	Raw    string
	Status int
	Date   string
	Key    string
}

// signParams 生成本次请求的 date 与 key（ov 可临时覆盖配置）。
func (j *Judge) signParams(ov *SignOverride) (date, key string) {
	unit, order, upper := j.cfg.DateUnit, j.cfg.KeyOrder, j.cfg.KeyUpper
	if ov != nil {
		switch ov.DateUnit {
		case "s", "ms", "datetime":
			unit = ov.DateUnit
		}
		switch ov.KeyOrder {
		case "date_first", "appkey_first":
			order = ov.KeyOrder
		}
		if ov.KeyUpper != nil {
			upper = *ov.KeyUpper
		}
	}
	now := time.Now()
	switch unit {
	case "ms":
		date = strconv.FormatInt(now.UnixMilli(), 10)
	case "datetime":
		date = now.Format("20060102150405")
	default:
		date = strconv.FormatInt(now.Unix(), 10)
	}
	raw := date + j.cfg.AppKey
	if order == "appkey_first" {
		raw = j.cfg.AppKey + date
	}
	sum := md5.Sum([]byte(raw))
	key = hex.EncodeToString(sum[:])
	if upper {
		key = strings.ToUpper(key)
	}
	return date, key
}

// ask 调用外部接口。criteria 为判定标准提示词，target 为文件路径+代码（可为空）。
// chat 模式：POST url?mode=message&date=<毫秒>&sign=<md5(date+APPKEY)>，content 放表单；
// openai 模式：POST <url>，Authorization: Bearer <app_key>，body 为标准 chat/completions。
func (j *Judge) ask(ctx context.Context, criteria, target string, ov *SignOverride) (askResponse, error) {
	u, err := url.Parse(j.cfg.URL)
	if err != nil {
		return askResponse{}, fmt.Errorf("接口地址非法: %w", err)
	}
	resp := askResponse{}
	var req *http.Request
	switch j.cfg.Type {
	case "openai":
		messages := []map[string]string{{"role": "user", "content": criteria}}
		if target != "" {
			messages = []map[string]string{
				{"role": "system", "content": criteria},
				{"role": "user", "content": target},
			}
		}
		payload, _ := json.Marshal(map[string]any{"model": j.cfg.Model, "messages": messages})
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
		if err != nil {
			return resp, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+j.cfg.AppKey)
	default: // chat
		resp.Date, resp.Key = j.signParams(ov)
		// mode/date/sign 走 URL（短参数）；content 放 POST 表单 —— 服务端 DNTRequest.GetString
		// 先查 QueryString 再查 Form，且 GET 方式会被 IIS 的 maxQueryString(默认2048) 拒掉
		q := u.Query()
		q.Set("mode", "message")
		q.Set("date", resp.Date)
		// 服务端实际读的是 sign（key 是文档里的叫法），两个都带上以兼容不同实现
		q.Set("sign", resp.Key)
		q.Set("key", resp.Key)
		u.RawQuery = q.Encode()

		form := url.Values{}
		form.Set("content", joinPrompt(criteria, target))
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
		if err != nil {
			return resp, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	httpResp, err := j.client.Do(req)
	if err != nil {
		return resp, err
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return resp, err
	}
	resp.Status = httpResp.StatusCode
	resp.Raw = strings.TrimSpace(string(body))
	if httpResp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("接口返回 %d: %s", httpResp.StatusCode, truncateRunes(string(body), 200))
	}
	if j.cfg.Type == "openai" {
		resp.Answer = extractOpenAI(body)
		if resp.Answer == "" {
			resp.Answer = extractAnswer(body)
		}
		return resp, nil
	}
	resp.Answer = extractAnswer(body)
	return resp, nil
}

// extractOpenAI 解析 OpenAI 兼容响应：choices[0].message.content。
func extractOpenAI(body []byte) string {
	var v struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &v) == nil && len(v.Choices) > 0 {
		return strings.TrimSpace(v.Choices[0].Message.Content)
	}
	return ""
}

// extractAnswer 从响应里取 AI 回答：优先常见 JSON 字段，否则当纯文本。
func extractAnswer(body []byte) string {
	text := strings.TrimSpace(string(body))
	var v any
	if json.Unmarshal(body, &v) == nil {
		if s := findString(v); s != "" {
			return strings.TrimSpace(s)
		}
	}
	return text
}

func findString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		for _, k := range []string{"answer", "data", "content", "message", "result", "msg", "text", "reply"} {
			if val, ok := t[k]; ok {
				if s := findString(val); s != "" {
					return s
				}
			}
		}
		for _, val := range t {
			if s := findString(val); s != "" {
				return s
			}
		}
	case []any:
		for _, item := range t {
			if s := findString(item); s != "" {
				return s
			}
		}
	}
	return ""
}

// parseVerdict 解析固定词汇。先认 MALICIOUS，避免 "UNSAFE"/"NOT SAFE" 之类的误判。
func parseVerdict(answer string) (Verdict, error) {
	up := strings.ToUpper(strings.TrimSpace(answer))
	switch {
	case strings.Contains(up, TokenMalicious), strings.Contains(up, "UNSAFE"), strings.Contains(up, "NOT SAFE"),
		strings.Contains(answer, "恶意"), strings.Contains(answer, "可疑"), strings.Contains(answer, "不安全"):
		return Malicious, nil
	case strings.Contains(up, TokenSafe), strings.Contains(answer, "安全"), strings.Contains(answer, "正常"), strings.Contains(answer, "良性"):
		return Safe, nil
	}
	return Unknown, errors.New("AI 回答无法识别为 SAFE/MALICIOUS")
}

// buildPrompt 构造固定输出格式的判定提示词。
// promptCriteria 判定标准（chat 模式作为提示词前半；openai 模式作为 system 消息）。
func promptCriteria() string {
	var b strings.Builder
	b.WriteString("你是 Windows IIS 服务器安全审计员。请判断下面这段网站脚本代码是不是 webshell/后门/挂马。\n")
	b.WriteString("判定 MALICIOUS（满足任意一条）：\n")
	b.WriteString("1. 存在真实执行链路：调用了 Process.Start / cmd.exe / powershell 等执行命令，或把 ProcessStartInfo 交给 Process 真正启动；\n")
	b.WriteString("2. 命令、路径或写入内容来自用户输入（Request/Form/QueryString/Cookie），或与 Base64/Hex 解码结果拼接后执行/写文件；\n")
	b.WriteString("3. 典型后门特征：eval/Execute/反射调用用户输入、口令校验后门、一句话木马、挂马注入(外链iframe/跳转)。\n")
	b.WriteString("判定 SAFE（满足任意一条且不存在上述 MALICIOUS 特征）：\n")
	b.WriteString("1. 仅 new 对象、定义函数/类、引入命名空间，从未实际执行（死代码/残留调试代码也算 SAFE）；\n")
	b.WriteString("2. 正常业务逻辑：页面渲染、数据库读写、日志、文件导出等；即使出现上述高危 API，只要参数是固定值且未真正执行，也算 SAFE。\n")
	b.WriteString("注意：Process.Start、File.WriteAllText、FromBase64String 等 API 也可能出现在正常业务代码里，请结合上下文判断意图，不要只看关键字。\n")
	b.WriteString("只输出一个词作为结论，不要输出解释、标点或其它内容：\n")
	b.WriteString("SAFE —— 正常业务代码，可以放行\n")
	b.WriteString("MALICIOUS —— 恶意代码（后门/命令执行/写文件/挂马等），必须拦截\n")
	return b.String()
}

// promptTarget 待审目标：文件路径 + 代码片段。
func promptTarget(path, content string, maxSnippet int) string {
	var b strings.Builder
	b.WriteString("\n文件路径: ")
	b.WriteString(path)
	b.WriteString("\n代码:\n")
	b.WriteString(snippet(content, maxSnippet))
	return b.String()
}

// joinPrompt 拼接完整提示词（chat 模式用）。
func joinPrompt(criteria, target string) string {
	if target == "" {
		return criteria
	}
	return criteria + target
}

// buildPrompt 完整提示词（保留给测试/调试）。
func buildPrompt(path, content string, maxSnippet int) string {
	return joinPrompt(promptCriteria(), promptTarget(path, content, maxSnippet))
}

// snippet 截断送审代码，避免 GET query 过长（超长部分用标记替代）。
func snippet(content string, max int) string {
	if max <= 0 || len(content) <= max {
		return content
	}
	cut := max
	for cut > 0 && !utf8RuneStart(content[cut]) { // 不切断 UTF-8 字符
		cut--
	}
	return content[:cut] + "\n...[代码过长已截断]"
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func (j *Judge) load() {
	if j.cfg.WhitelistFile == "" {
		return
	}
	data, err := os.ReadFile(j.cfg.WhitelistFile)
	if err != nil {
		return
	}
	var f whitelistFile
	if json.Unmarshal(data, &f) != nil {
		return
	}
	for _, e := range f.Items {
		sha := strings.ToLower(strings.TrimSpace(e.SHA256))
		if sha == "" {
			continue
		}
		e.SHA256 = sha
		j.entries[sha] = e
	}
}

// saveLocked 原子写白名单（调用方需持有 mu）。
func (j *Judge) saveLocked() error {
	if j.cfg.WhitelistFile == "" {
		return errors.New("未配置 ai_judge.whitelist_file")
	}
	items := make([]Entry, 0, len(j.entries))
	for _, e := range j.entries {
		items = append(items, e)
	}
	sort.Slice(items, func(a, b int) bool { return items[a].Time < items[b].Time })
	data, err := json.MarshalIndent(whitelistFile{Items: items}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(j.cfg.WhitelistFile, append(data, '\n'))
}

// writeFileAtomic 先写临时文件再 rename，避免进程中途退出留下半个 JSON。
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
