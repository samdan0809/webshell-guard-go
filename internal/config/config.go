// Package config 负责加载与校验配置。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// WebhookConfig webhook 相关配置。
type WebhookConfig struct {
	URL     string `yaml:"url"`
	Type    string `yaml:"type"` // generic | dingtalk | feishu | wecom
	Timeout int    `yaml:"timeout"`
	Retry   int    `yaml:"retry"`
}

// UIConfig 内置 Web 可视面板配置。
type UIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Token   string `yaml:"token"` // 面板访问口令(HTTP Basic 密码)，留空则启动时自动生成并打印到日志
}

// BaselineConfig 基线相关配置。
type BaselineConfig struct {
	Enabled bool   `yaml:"enabled"`
	File    string `yaml:"file"`
}

// RulesSyncConfig 规则库同步配置。
type RulesSyncConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Mode       string   `yaml:"mode"`        // git | raw
	Repo       string   `yaml:"repo"`        // git 模式: 仓库地址(可含凭据)；raw 模式: raw 文件 URL 或目录前缀
	Branch     string   `yaml:"branch"`      // git 模式分支
	Interval   int      `yaml:"interval"`    // 拉取周期(秒)
	Token      string   `yaml:"token"`       // raw 模式认证 token
	AuthHeader string   `yaml:"auth_header"` // raw 模式认证头(默认 Authorization: Bearer {token})
	Files      []string `yaml:"files"`       // raw 模式: repo 为目录前缀时要拉取的文件名列表；为空则 repo 视为单个文件 URL
}

// UpdateConfig 程序自升级配置。
type UpdateConfig struct {
	Enabled    bool   `yaml:"enabled"`    // 定时检查远端版本
	AutoApply  bool   `yaml:"auto_apply"` // 发现新版本自动下载替换并重启生效(默认 false, 仅提示)
	URL        string `yaml:"url"`        // 升级清单(manifest JSON)地址: {"version":"v1.0.1","url":"...exe","sha256":"...","notes":"..."}
	Interval   int    `yaml:"interval"`   // 检查周期(秒)
	Token      string `yaml:"token"`      // 认证 token(可填充到 auth_header 的 {token} 占位)
	AuthHeader string `yaml:"auth_header"`
}

// AIJudgeConfig AI 复核配置：命中风险字符的文件先送 AI 判定安全/恶意。
type AIJudgeConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Type          string   `yaml:"type"`           // chat(自建chat.ashx,默认) | openai(OpenAI兼容接口)
	URL           string   `yaml:"url"`            // chat: http://host/api/open/chat.ashx；openai: https://host/v1/chat/completions
	AppKey        string   `yaml:"app_key"`        // chat: 参与MD5签名的APPKEY；openai: 作为 Bearer key
	Model         string   `yaml:"model"`          // openai 模式必填，如 gpt-4o-mini / deepseek-chat
	Timeout       int      `yaml:"timeout"`        // 单次请求超时(秒)
	Keywords      []string `yaml:"keywords"`       // 风险字符(正则)，留空用内置默认
	WhitelistFile string   `yaml:"whitelist_file"` // AI 判定安全后的永久白名单(按 SHA256)
	// 签名方式：不同接口实现不同，按接口文档填写（面板"测试 AI 接口"可临时试）
	DateUnit string `yaml:"date_unit"` // s(秒,默认) | ms(毫秒) | datetime(yyyyMMddHHmmss)
	KeyOrder string `yaml:"key_order"` // date_first(时间戳+APPKEY,默认) | appkey_first(APPKEY+时间戳)
	KeyUpper bool   `yaml:"key_upper"` // MD5 是否转大写
}

// Config 全局配置。
type Config struct {
	WatchDirs       []string        `yaml:"watch_dirs"`
	Extensions      []string        `yaml:"extensions"`
	ScanInterval    time.Duration   `yaml:"scan_interval"`
	Debounce        time.Duration   `yaml:"debounce"`
	MaxFileSize     int64           `yaml:"max_file_size"`
	ScoreThreshold  int             `yaml:"score_threshold"`
	Action          string          `yaml:"action"` // quarantine | delete | alert
	QuarantineDir   string          `yaml:"quarantine_dir"`
	Webhook         WebhookConfig   `yaml:"webhook"`
	UI              UIConfig        `yaml:"ui"`
	Baseline        BaselineConfig  `yaml:"baseline"`
	RulesSync       RulesSyncConfig `yaml:"rules_sync"`
	AIJudge         AIJudgeConfig   `yaml:"ai_judge"`
	Update          UpdateConfig    `yaml:"update"`
	IgnoreDirs      []string        `yaml:"ignore_dirs"`
	DomainWhitelist []string        `yaml:"external_domain_whitelist"`
	WhitelistHashes []string        `yaml:"whitelist_hashes"`
	HashWhitelist   map[string]bool `yaml:"-"` // 运行时构建
	AlertCooldown   time.Duration   `yaml:"alert_cooldown"`
	LogFile         string          `yaml:"log_file"`
	ExtraKeywords   map[string]int  `yaml:"extra_rules"` // 自定义规则: 正则 -> 权重
}

// Load 从指定路径加载配置文件。
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("配置路径非法: %w", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("读取配置失败: %w", err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// 相对路径统一按配置文件所在目录解析：服务模式工作目录是 C:\Windows\System32，
	// 直接用 ./xxx 会把日志/隔离区/基线写到系统目录里。
	base := filepath.Dir(abs)
	cfg.QuarantineDir = resolvePath(base, cfg.QuarantineDir)
	cfg.Baseline.File = resolvePath(base, cfg.Baseline.File)
	cfg.LogFile = resolvePath(base, cfg.LogFile)
	cfg.AIJudge.WhitelistFile = resolvePath(base, cfg.AIJudge.WhitelistFile)
	return cfg, nil
}

// resolvePath 把相对路径解析到 base 目录，绝对路径原样返回。
func resolvePath(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

// validate 校验并补全默认值。
func (c *Config) validate() error {
	// watch_dirs 允许为空：部署时先装服务，再在面板「设置」页热填监控目录。
	for i, d := range c.WatchDirs {
		abs, err := filepath.Abs(strings.TrimSpace(d))
		if err != nil {
			return fmt.Errorf("watch_dirs[%d] 路径非法: %w", i, err)
		}
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			return fmt.Errorf("watch_dirs[%d] 目录不存在或不是目录: %s", i, abs)
		}
		c.WatchDirs[i] = abs
	}
	if len(c.Extensions) == 0 {
		c.Extensions = []string{".aspx", ".ashx", ".ascx", ".php", ".jsp", ".jspx"}
	}
	for i := range c.Extensions {
		c.Extensions[i] = strings.ToLower(strings.TrimSpace(c.Extensions[i]))
		if !strings.HasPrefix(c.Extensions[i], ".") {
			c.Extensions[i] = "." + c.Extensions[i]
		}
	}
	if c.ScanInterval <= 0 {
		c.ScanInterval = 10 * time.Minute
	}
	if c.Debounce <= 0 {
		c.Debounce = 500 * time.Millisecond
	}
	if c.MaxFileSize <= 0 {
		c.MaxFileSize = 5 * 1024 * 1024
	}
	if c.ScoreThreshold <= 0 {
		c.ScoreThreshold = 6
	}
	switch c.Action {
	case "":
		c.Action = "quarantine"
	case "quarantine", "delete", "alert":
	default:
		return fmt.Errorf("action 只支持 quarantine/delete/alert, 当前: %s", c.Action)
	}
	if c.QuarantineDir == "" {
		c.QuarantineDir = "./quarantine"
	}
	if c.Webhook.Type == "" {
		c.Webhook.Type = "generic"
	}
	if !c.UI.Enabled && c.UI.Port == 0 {
		c.UI.Enabled = true // 未配置时默认开启面板
	}
	if c.UI.Port <= 0 {
		c.UI.Port = 9090
	}
	if c.Webhook.Timeout <= 0 {
		c.Webhook.Timeout = 10
	}
	if c.Webhook.Retry <= 0 {
		c.Webhook.Retry = 3
	}
	if c.Baseline.File == "" {
		c.Baseline.File = "./baseline.json"
	}
	if c.AlertCooldown <= 0 {
		c.AlertCooldown = 60 * time.Second
	}
	if c.HashWhitelist == nil {
		c.HashWhitelist = map[string]bool{}
		for _, h := range c.WhitelistHashes {
			c.HashWhitelist[strings.ToLower(h)] = true
		}
	}
	if c.LogFile == "" {
		c.LogFile = "./webshell-guard.log"
	}
	if c.AIJudge.WhitelistFile == "" {
		c.AIJudge.WhitelistFile = "./ai_whitelist.json"
	}
	if c.AIJudge.Enabled {
		if strings.TrimSpace(c.AIJudge.URL) == "" {
			return fmt.Errorf("ai_judge.enabled=true 时必须配置 ai_judge.url")
		}
		if c.AIJudge.Timeout <= 0 {
			c.AIJudge.Timeout = 20
		}
	}
	if c.Update.Interval <= 0 {
		c.Update.Interval = 3600
	}
	if c.Update.Enabled && strings.TrimSpace(c.Update.URL) == "" {
		return fmt.Errorf("update.enabled=true 时必须配置 update.url(升级清单 JSON 地址)")
	}
	if c.Update.Enabled && c.Update.AuthHeader == "" && c.Update.Token != "" {
		c.Update.AuthHeader = "Authorization: Bearer {token}"
	}
	if c.RulesSync.Enabled {
		switch c.RulesSync.Mode {
		case "":
			c.RulesSync.Mode = "git"
		case "git", "raw":
		default:
			return fmt.Errorf("rules_sync.mode 只支持 git/raw, 当前: %s", c.RulesSync.Mode)
		}
		if c.RulesSync.Repo == "" {
			return fmt.Errorf("rules_sync.enabled 时 repo 不能为空")
		}
		if c.RulesSync.Mode == "git" && c.RulesSync.Branch == "" {
			c.RulesSync.Branch = "main"
		}
		if c.RulesSync.Interval <= 0 {
			c.RulesSync.Interval = 300
		}
	}
	return nil
}

// IsWatchedExt 判断扩展名是否在监控列表中。
func (c *Config) IsWatchedExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	for _, e := range c.Extensions {
		if ext == e {
			return true
		}
	}
	return false
}

// IsIgnoredDir 判断路径中是否包含被忽略的目录段。
func (c *Config) IsIgnoredDir(path string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		for _, ig := range c.IgnoreDirs {
			if ig != "" && strings.EqualFold(seg, ig) {
				return true
			}
		}
	}
	return false
}
