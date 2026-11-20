// Package detector 实现 webshell / 挂马检测引擎。
package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"strings"
	"sync"
)

// Kind 威胁类别。
type Kind string

const (
	KindWebshell Kind = "webshell"
	KindHorse    Kind = "挂马"
)

// Rule 单条检测规则。
type Rule struct {
	ID       string
	Kind     Kind
	Score    int
	Pattern  *regexp.Regexp
	Desc     string
	// Combination 为 true 时表示该规则由多条子正则组成，需全部命中才计分。
	Combination  bool
	PatternAll   []*regexp.Regexp
}

// Hit 命中记录。
type Hit struct {
	RuleID string `json:"rule_id"`
	Kind   Kind   `json:"kind"`
	Score  int    `json:"score"`
	Desc   string `json:"desc"`
	Line   int    `json:"line"` // 首次命中行号，从 1 开始，0 表示未知
	Detail string `json:"detail"`
}

// Result 检测结果。
type Result struct {
	Clean   bool
	Score   int
	Hits    []Hit
	SHA256  string
	Size    int64
}

func mustCompile(s string) *regexp.Regexp {
	return regexp.MustCompile("(?i)" + s)
}

// Detect 热路径用到的正则，包级编译一次，避免每次调用重复编译。
var (
	reExtSrc = mustCompile(`<(iframe|script)[^>]+src\s*=\s*["']https?://([^/"'\\]+)|<meta[^>]+http-equiv\s*=\s*["']?refresh[^>]+url\s*=\s*https?://([^/"'\\]+)`)
	reSrc    = mustCompile(`src\s*=\s*(["'])https?://([^/"'\\]+)`)
	reDocWriteUnesc = regexp.MustCompile(`(?is)document\.write\s*\(\s*unescape\s*\(\s*"(.*?)"\s*\)\s*\)|document\.write\s*\(\s*unescape\s*\(\s*'(.*?)'\s*\)\s*\)`)
)


// RuleInfo 规则摘要（面板展示用）。
type RuleInfo struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Score       int    `json:"score"`
	Desc        string `json:"desc"`
	Combination bool   `json:"combination"`
}

// BuiltinRuleInfos 返回内置规则摘要列表。
func BuiltinRuleInfos() []RuleInfo {
	out := make([]RuleInfo, 0, len(builtinRules))
	for _, r := range builtinRules {
		out = append(out, RuleInfo{ID: r.ID, Kind: string(r.Kind), Score: r.Score, Desc: r.Desc, Combination: r.Combination})
	}
	return out
}

// 内置规则库。命名与权重经过调优：
// 强特征（单条即接近阈值）、弱特征（需组合）分开。
var builtinRules = []*Rule{
	// ===== webshell: 命令执行 =====
	{ID: "WS-EXEC-CMD", Kind: KindWebshell, Score: 5, Combination: true, Desc: "Process.Start + cmd.exe 命令执行后门",
		PatternAll: []*regexp.Regexp{
			mustCompile(`Process\.Start(Info)?`),
			mustCompile(`cmd\.exe|/c\s|cmd /c`),
		}},
	{ID: "WS-EXEC-REQ", Kind: KindWebshell, Score: 4, Combination: true, Desc: "命令执行与请求参数组合(Request+Process)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`Request(\.|\[)`),
			mustCompile(`Process\.Start`),
		}},
	// ===== webshell: 写文件后门（本案同款） =====
	{ID: "WS-WRITE-B64", Kind: KindWebshell, Score: 6, Combination: true, Desc: "Base64解码后写入任意文件(写文件后门)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`Convert\.FromBase64String`),
			mustCompile(`File\.WriteAll(Text|Bytes)`),
		}},
	{ID: "WS-REQ-WRITE", Kind: KindWebshell, Score: 4, Combination: true, Desc: "请求参数控制文件写入(Request+WriteAll)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`Request(\.|\[)`),
			mustCompile(`WriteAll(Text|Bytes)\s*\(`),
		}},
	// ===== webshell: 动态编译 =====
	{ID: "WS-CSC-COMPILE", Kind: KindWebshell, Score: 6, Pattern: mustCompile(`CSharpCodeProvider|Microsoft\.CSharp|CompileAssemblyFrom`), Desc: "动态编译C#代码(常见加密webshell)"},
	// ===== webshell: 经典一句话 =====
	{ID: "WS-EVAL-REQ", Kind: KindWebshell, Score: 10, Pattern: mustCompile(`<%@\s*\w+[^>]*%>\s*<%\s*eval\s*\(?\s*request|<%\s*eval\s*request|ExecuteGlobal\s*\(?\s*request`), Desc: "经典一句话木马(eval/ExecuteGlobal+request)"},
	{ID: "ASP-EXEC-REQ", Kind: KindWebshell, Score: 8, Pattern: mustCompile(`\b(execute|ExecuteGlobal|executeGlobal)\s*\(?\s*request\b`), Desc: "execute+request 一句话(ASP变种)"},
	{ID: "ASPX-JSCRIPT-EVAL", Kind: KindWebshell, Score: 9, Pattern: mustCompile(`eval\s*\(\s*Request(\.Item|\.Form|\.QueryString|\[|\()`), Desc: "JScript.NET 一句话(eval(Request.Item))"},
	{ID: "ASPX-REFLECT-LOAD", Kind: KindWebshell, Score: 6, Combination: true, Desc: "反射方法调用+用户输入(变形后门)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`GetMethod\s*\(|GetType\s*\([^)]*\)\s*\.|InvokeMember\s*\(`),
			mustCompile(`\.Invoke\s*\(|InvokeMember\s*\(`),
			mustCompile(`Request(\.|\[)`),
		}},
	{ID: "ASP-EVAL-SPLIT", Kind: KindWebshell, Score: 7, Pattern: mustCompile(`(e""v""a""l|ev\s*al|eval_r)\s*\(?request`), Desc: "拆分/注释变形的一句话(防替换写法)"},
	{ID: "WS-FSO-SAVE", Kind: KindWebshell, Score: 5, Combination: true, Desc: "FSO对象写文件(ASP后门)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`Scripting\.FileSystemObject`),
			mustCompile(`SaveToFile|OpenTextFile.*,\s*2`),
		}},
	{ID: "WS-SHELL-OBJ", Kind: KindWebshell, Score: 8, Pattern: mustCompile(`WScript\.Shell|Shell\.Application|SheLL\.CriAte`), Desc: "Shell对象调用(常见后门)"},
	{ID: "WS-SERVER-EXEC-REQ", Kind: KindWebshell, Score: 6, Combination: true, Desc: "Server.Execute/Include 请求参数控制",
		PatternAll: []*regexp.Regexp{
			mustCompile(`Server\.(Execute|Transfer|MapPath)`),
			mustCompile(`Request(\.|\[)`),
		}},
	// ===== webshell: ASPX 特有降防配置（本案同款） =====
	{ID: "WS-DEGRADE-SEC", Kind: KindWebshell, Score: 4, Combination: true, Desc: "关闭ViewStateMAC/事件校验等安全配置",
		PatternAll: []*regexp.Regexp{
			mustCompile(`EnableViewStateMac\s*=\s*false|EnableEventValidation\s*=\s*false|ViewStateEncryptionMode\.Never`),
			mustCompile(`Request(\.|\[)`), // 与用户输入组合才计分
		}},
	// ===== webshell: 反射加载/加密payload =====
	{ID: "WS-ASSEMBLY-LOAD", Kind: KindWebshell, Score: 5, Combination: true, Desc: "反射加载字节数组(内存马特征)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`Assembly\.Load|Activator\.CreateInstance|GetType\(`),
			mustCompile(`Convert\.FromBase64String|FromBase64`),
		}},
	{ID: "WS-XOR-DECODE", Kind: KindWebshell, Score: 4, Pattern: mustCompile(`(unserialize|gzinflate|base64_decode|str_rot13)\s*\(\s*(gzinflate|base64_decode|str_rot13)\s*\(`), Desc: "多层解码混淆(PHP常见,含跨用)"},

	// ===== webshell: PHP =====
	{ID: "PHP-EVAL-REQ", Kind: KindWebshell, Score: 9, Pattern: mustCompile(`\beval\s*\(\s*\$(_POST|_GET|_REQUEST|GLOBALS|SERVER)`), Desc: "eval直接执行用户输入(PHP一句话)"},
	{ID: "PHP-EVAL-DECODE", Kind: KindWebshell, Score: 9, Pattern: mustCompile(`\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(`), Desc: "eval+解码函数(加密PHP后门)"},
	{ID: "PHP-ASSERT-REQ", Kind: KindWebshell, Score: 9, Pattern: mustCompile(`\bassert\s*\(\s*\$(_POST|_GET|_REQUEST|GLOBALS)`), Desc: "assert执行用户输入(PHP后门)"},
	{ID: "PHP-CMD-REQ", Kind: KindWebshell, Score: 5, Combination: true, Desc: "命令执行函数+用户输入组合",
		PatternAll: []*regexp.Regexp{
			mustCompile(`\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(`),
			mustCompile(`\$_(POST|GET|REQUEST|COOKIE|SERVER)`),
		}},
	{ID: "PHP-WRITE-REQ", Kind: KindWebshell, Score: 5, Combination: true, Desc: "文件写入函数+用户输入组合(写文件后门)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`\b(file_put_contents|fwrite|fputs)\s*\(`),
			mustCompile(`\$_(POST|GET|REQUEST)`),
		}},
	{ID: "PHP-VAR-CALLBACK", Kind: KindWebshell, Score: 6, Combination: true, Desc: "回调函数执行用户输入(变形PHP后门)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`\b(call_user_func|call_user_func_array|array_map|array_filter|usort|preg_replace_callback|create_function|register_shutdown_function)\s*\(`),
			mustCompile(`\$_(POST|GET|REQUEST)`),
		}},
	{ID: "PHP-PREG-E", Kind: KindWebshell, Score: 7, Pattern: mustCompile(`preg_replace\s*\(\s*["'][^"']*/e[a-z]*["']`), Desc: "preg_replace /e 代码执行( PHP后门)"},
	{ID: "PHP-INCLUDE-REQ", Kind: KindWebshell, Score: 5, Combination: true, Desc: "动态包含用户输入(文件包含后门)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`\b(include|include_once|require|require_once)\s*\(?\s*\$`),
			mustCompile(`\$_(POST|GET|REQUEST)`),
		}},
	{ID: "PHP-VAR-FUNC-DEF", Kind: KindWebshell, Score: 6, Pattern: mustCompile(`\$_(POST|GET|REQUEST)\s*\[[^\]]*\]\s*\(\s*\$`), Desc: "变量函数直接调用($_POST[..]($..))"},
	// --- PHP 变种写法 ---
	{ID: "PHP-ASSERT-STR", Kind: KindWebshell, Score: 7, Combination: true, Desc: "assert以字符串形式中转变量函数",
		PatternAll: []*regexp.Regexp{
			mustCompile(`['"]assert['"]`),
			mustCompile(`\$_(POST|GET|REQUEST|COOKIE)`),
		}},
	{ID: "PHP-VAR-FUNC-MID", Kind: KindWebshell, Score: 6, Combination: true, Desc: "用户输入赋值后变量函数调用(中转执行)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`\$\w+\s*=\s*\$_(POST|GET|REQUEST|COOKIE)`),
			mustCompile(`\$\w+\s*\(\s*\$`),
		}},
	{ID: "PHP-BACKTICK-REQ", Kind: KindWebshell, Score: 7, Combination: true, Desc: "反引号执行用户输入(PHP变种)",
		PatternAll: []*regexp.Regexp{
			mustCompile("\\x60"),
			mustCompile(`\$_(POST|GET|REQUEST|COOKIE)`),
		}},
	{ID: "PHP-EXTRACT-REQ", Kind: KindWebshell, Score: 7, Pattern: mustCompile(`extract\s*\(\s*\$(_POST|_GET|_REQUEST)`), Desc: "extract变量覆盖后门"},
	{ID: "PHP-PHPINPUT-EXEC", Kind: KindWebshell, Score: 7, Combination: true, Desc: "php://input 读取+代码执行",
		PatternAll: []*regexp.Regexp{
			mustCompile(`php://input`),
			mustCompile(`\beval\s*\(|\bassert\s*\(|include\s*\(|require\s*\(`),
		}},
	{ID: "PHP-SYSCALL-DECODE", Kind: KindWebshell, Score: 7, Combination: true, Desc: "命令执行函数+解码输入(加密命令)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(`),
			mustCompile(`base64_decode|gzinflate|str_rot13|hex2bin|pack\s*\(`),
		}},
	{ID: "PHP-CHR-CHAIN", Kind: KindWebshell, Score: 7, Combination: true, Desc: "chr拼接构造代码/assert(chr链)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`\bassert\b|\beval\b`),
			mustCompile(`chr\(\s*\d+\s*\)\s*\.\s*chr\(`),
		}},
	{ID: "PHP-STRCAT-CALL", Kind: KindWebshell, Score: 6, Combination: true, Desc: "字符串拼接函数名+变量调用(拆分变形)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`["'][a-z_]{2,12}["']\s*\.\s*["'][a-z_]{2,12}["']`),
			mustCompile(`\$\w+\s*\(\s*\$`),
			mustCompile(`\$_(POST|GET|REQUEST|COOKIE)`),
		}},
	{ID: "PHP-OBFUS-HEX", Kind: KindWebshell, Score: 6, Combination: true, Desc: "十六进制转义混淆+动态执行(无字母马)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`(\\x[0-9a-fA-F]{2}){12,}`),
			mustCompile(`\beval\b|\bassert\b|preg_replace|call_user_func|array_map`),
		}},
	{ID: "PHP-NOALPHA", Kind: KindWebshell, Score: 6, Pattern: mustCompile(`\$_\[\]\s*=\s*@_\s*\+|\$__\[\]\s*=`), Desc: "无字母数字webshell(自增构造)特征"},

	// ===== webshell: JSP =====
	{ID: "JSP-RUNTIME-EXEC", Kind: KindWebshell, Score: 5, Pattern: mustCompile(`Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec`), Desc: "Runtime.exec 命令执行(JSP后门)"},
	{ID: "JSP-PROCESSBUILDER", Kind: KindWebshell, Score: 7, Pattern: mustCompile(`new\s+ProcessBuilder\s*\(`), Desc: "ProcessBuilder 命令执行"},
	{ID: "JSP-EXEC-REQ", Kind: KindWebshell, Score: 5, Combination: true, Desc: "命令执行+请求参数组合",
		PatternAll: []*regexp.Regexp{
			mustCompile(`getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder`),
			mustCompile(`request\s*\.\s*getParameter|getParameter\s*\(|getHeader\s*\(|getInputStream\s*\(`),
		}},
	{ID: "JSP-WRITE-REQ", Kind: KindWebshell, Score: 5, Combination: true, Desc: "文件写入+请求参数组合(写文件后门)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`FileOutputStream|FileWriter|Files\s*\.\s*write`),
			mustCompile(`request\s*\.\s*getParameter|getParameter\s*\(|getHeader\s*\(|getInputStream\s*\(`),
		}},
	{ID: "JSP-REFLECT-RUNTIME", Kind: KindWebshell, Score: 7, Combination: true, Desc: "反射调用Runtime/Method(变形命令执行)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`Class\s*\.\s*forName|\.class\s*\.`),
			mustCompile(`getMethod\s*\(|getDeclaredMethod\s*\(|\.invoke\s*\(`),
		}},
	{ID: "JSP-EL-INJECT", Kind: KindWebshell, Score: 6, Pattern: mustCompile(`\$\{\s*(Runtime|ProcessBuilder|ScriptEngine|T\s*\()`), Desc: "EL表达式注入执行(Java变种)"},
	{ID: "JSP-SCRIPT-ENGINE", Kind: KindWebshell, Score: 7, Pattern: mustCompile(`ScriptEngineManager|getEngineByName|getBindings|eval\s*\(\s*reader`), Desc: "脚本引擎动态执行(JSP内存马)"},
	{ID: "JSP-DYN-COMPILE", Kind: KindWebshell, Score: 7, Pattern: mustCompile(`getSystemJavaCompiler|JavaCompiler|JavaFileObjects|JspRuntimeLibrary`), Desc: "动态编译Java代码(内存马/后门)"},
	{ID: "JSP-CLASSLOAD", Kind: KindWebshell, Score: 6, Combination: true, Desc: "动态加载字节码(内存马特征)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`defineClass\s*\(|ClassLoader|loadClass\s*\(`),
			mustCompile(`getParameter|Base64|decode`),
		}},
	{ID: "JSP-FILTER-REG", Kind: KindWebshell, Score: 6, Pattern: mustCompile(`addMappingForUrlPatterns|registerFilter|addListener\s*\(|addFilterDef`), Desc: "动态注册Filter/Listener(内存马)"},

	// ===== 挂马: 外部 iframe/script 注入 =====
	{ID: "HM-IFRAME-EXT", Kind: KindHorse, Score: 5, Pattern: mustCompile(`<iframe[^>]+src\s*=\s*["']https?://[^"']+["']`), Desc: "外部iframe嵌入(挂马)"},
	{ID: "HM-IFRAME-HIDDEN", Kind: KindHorse, Score: 8, Pattern: mustCompile(`<iframe[^>]+(width\s*=\s*["']?0|height\s*=\s*["']?0|display\s*:\s*none|visibility\s*:\s*hidden)[^>]*>`), Desc: "隐藏iframe(典型挂马)"},
	{ID: "HM-SCRIPT-EXT", Kind: KindHorse, Score: 3, Pattern: mustCompile(`<script[^>]+src\s*=\s*["']https?://[^"']+["']`), Desc: "外部script引用(疑似挂马)"},
	{ID: "HM-DOC-WRITE-UNESC", Kind: KindHorse, Score: 7, Pattern: mustCompile(`document\.write\s*\(\s*unescape\s*\(`), Desc: "document.write(unescape())混淆注入"},
	{ID: "HM-PACKED-EVAL", Kind: KindHorse, Score: 7, Pattern: mustCompile(`eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e`), Desc: "eval打包混淆(rldecode,挂马常用)"},
	{ID: "HM-IFRAME-NOSCRIPT", Kind: KindHorse, Score: 5, Pattern: mustCompile(`<noscript>\s*<iframe`), Desc: "noscript内嵌iframe(暗链/挂马)"},
	{ID: "HM-JS-TROJAN-STR", Kind: KindHorse, Score: 6, Pattern: mustCompile(`function\s*\(\s*\)\s*\{\s*var\s+\w+\s*=\s*['"][0-9a-f]{200,}`), Desc: "超长十六进制串(挂马JS特征)"},
	// --- 挂马变种 ---
	{ID: "HM-IFRAME-SRCDOC", Kind: KindHorse, Score: 6, Pattern: mustCompile(`<iframe[^>]+srcdoc\s*=`), Desc: "iframe srcdoc 注入(挂马变种)"},
	{ID: "HM-ATOB-INJECT", Kind: KindHorse, Score: 7, Combination: true, Desc: "atob解码后写入页面(编码挂马)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`\batob\s*\(|unescape\s*\(`),
			mustCompile(`document\.write\s*\(|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML`),
		}},
	{ID: "HM-META-REFRESH", Kind: KindHorse, Score: 5, Pattern: mustCompile(`<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+url\s*=\s*https?://`), Desc: "meta refresh 跳转(劫持/挂马变种)"},
	{ID: "HM-SETTIMEOUT-EVAL", Kind: KindHorse, Score: 6, Combination: true, Desc: "延迟eval执行(绕静态分析)",
		PatternAll: []*regexp.Regexp{
			mustCompile(`setTimeout\s*\(\s*["']|setInterval\s*\(\s*["']`),
			mustCompile(`\beval\s*\(`),
		}},
	{ID: "HM-BASE64-SCRIPT", Kind: KindHorse, Score: 6, Pattern: mustCompile(`data\s*:\s*text/html\s*;\s*base64\s*,`), Desc: "data:text/html;base64 内嵌页(挂马变种)"},
}

// Detector 检测器。
type Detector struct {
	mu           sync.Mutex
	threshold    int
	domainWL     map[string]bool
	builtin      []*Rule // 当前生效的内置规则集（= 基线 + 同 ID 覆盖）
	builtinBase  []*Rule // 基线（代码默认或 rules_builtin.yaml），用于每次重算覆盖
	extraRules   []*Rule
}

// SetThreshold 运行时调整判恶阈值。
func (d *Detector) SetThreshold(n int) {
	if n <= 0 {
		return
	}
	d.mu.Lock()
	d.threshold = n
	d.mu.Unlock()
}

// SetDomainWhitelist 运行时替换外链域名白名单。
func (d *Detector) SetDomainWhitelist(domains []string) {
	wl := make(map[string]bool, len(domains))
	for _, dom := range domains {
		if dom = normalizeHost(dom); dom != "" {
			wl[dom] = true
		}
	}
	d.mu.Lock()
	d.domainWL = wl
	d.mu.Unlock()
}

// SetExtraRules 运行时替换自定义规则。
func (d *Detector) SetExtraRules(m map[string]int) {
	var rules []*Rule
	for pattern, score := range m {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			continue
		}
		rules = append(rules, &Rule{ID: "EX-" + shortHash(pattern), Kind: KindWebshell, Score: score, Pattern: re, Desc: "自定义规则"})
	}
	d.mu.Lock()
	d.extraRules = rules
	d.mu.Unlock()
}

// SetCustomRules 运行时替换自定义规则（完整定义版，规则库后台使用）。
// 调用方需保证规则正则可编译。
func (d *Detector) SetCustomRules(rules []*Rule) {
	d.mu.Lock()
	d.extraRules = rules
	d.mu.Unlock()
}

// New 创建检测器。
func New(threshold int, domainWhitelist []string, extraRules map[string]int) *Detector {
	if threshold <= 0 {
		threshold = 6
	}
	wl := make(map[string]bool, len(domainWhitelist))
	for _, d := range domainWhitelist {
		if d = normalizeHost(d); d != "" {
			wl[d] = true
		}
	}
	var extras []*Rule
	for pattern, score := range extraRules {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			continue // 自定义规则非法则忽略，日志由上层输出
		}
		extras = append(extras, &Rule{ID: "EX-" + shortHash(pattern), Kind: KindWebshell, Score: score, Pattern: re, Desc: "自定义规则"})
	}
	return &Detector{threshold: threshold, domainWL: wl, builtin: builtinRules, builtinBase: builtinRules, extraRules: extras}
}

// SetBuiltinRules 替换内置规则集（用于从 yaml 文件/共享规则加载，避免改规则需重编译）。
// rules 为 nil 或空时恢复代码默认内置规则。
func (d *Detector) SetBuiltinRules(rules []*Rule) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(rules) == 0 {
		rules = builtinRules
	}
	d.builtin = rules
	d.builtinBase = rules
}

// BuiltinRules 返回当前生效的内置规则集副本。
func (d *Detector) BuiltinRules() []*Rule {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*Rule, len(d.builtin))
	copy(out, d.builtin)
	return out
}

// BuiltinBaseRules 返回未经自定义覆盖的内置规则基线副本（每次重算覆盖都基于它）。
func (d *Detector) BuiltinBaseRules() []*Rule {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*Rule, len(d.builtinBase))
	copy(out, d.builtinBase)
	return out
}

// SetBuiltinOverrides 基于基线应用同 ID 覆盖，重算当前生效的内置规则集。
func (d *Detector) SetBuiltinOverrides(base, active []*Rule) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.builtinBase = base
	d.builtin = active
}

// Threshold 返回判恶分值线。
func (d *Detector) Threshold() int { return d.threshold }

// Detect 对文件内容执行全量规则检测。
func (d *Detector) Detect(content string, fileSize int64) Result {
	res := Result{Clean: true, Size: fileSize}
	res.SHA256 = hashString(content)

	// 先中和已知安全片段：白名单 CDN 引用、第三方统计代码（如 CNZZ）的 document.write(unescape())
	content = neutralizeKnownSafe(content)
	content = d.neutralizeWhitelisted(content)

	lines := strings.Split(content, "\n")

	hitFromRule := func(r *Rule, detail string) Hit {
		h := Hit{RuleID: r.ID, Kind: r.Kind, Score: r.Score, Desc: r.Desc, Detail: detail}
		// 找首个命中行号
		if r.Pattern != nil {
			for i, line := range lines {
				if r.Pattern.MatchString(line) {
					h.Line = i + 1
					break
				}
			}
		} else {
			for i, line := range lines {
				all := true
				for _, p := range r.PatternAll {
					if !p.MatchString(line) {
						all = false
						break
					}
				}
				if all {
					h.Line = i + 1
					break
				}
			}
		}
		return h
	}

	appendHit := func(r *Rule, detail string) {
		res.Clean = false
		res.Score += r.Score
		res.Hits = append(res.Hits, hitFromRule(r, detail))
	}

	check := func(r *Rule) {
		if r.Combination {
			allMatch := true
			for _, p := range r.PatternAll {
				if !p.MatchString(content) {
					allMatch = false
					break
				}
			}
			if allMatch {
				appendHit(r, "")
			}
			return
		}
		if loc := r.Pattern.FindString(content); loc != "" {
			appendHit(r, truncate(loc, 120))
		}
	}

	d.mu.Lock()
	builtin := d.builtin
	d.mu.Unlock()
	for _, r := range builtin {
		check(r)
	}
	for _, r := range d.extraRules {
		check(r)
	}

	// 挂马专项：外部域校验（白名单内不算挂马）
	d.checkExternalURLs(content, &res)

	return res
}

// checkExternalURLs 检查 iframe/script 引用及 meta refresh 跳转的外链域是否可疑。
func (d *Detector) checkExternalURLs(content string, res *Result) {
	re := reExtSrc
	matches := re.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		host := m[2]
		if host == "" {
			host = m[3]
		}
		if host == "" {
			continue
		}
		if d.domainWL[normalizeHost(host)] {
			continue
		}
		// 引用外部域：弱信号，+2 分
		res.Score += 2
		res.Clean = false
		res.Hits = append(res.Hits, Hit{
			RuleID: "HM-EXT-DOMAIN", Kind: KindHorse, Score: 2,
			Desc: "引用外部域名(非白名单)", Detail: m[0],
		})
	}
}

// normalizeHost 把 URL 中的主机归一化为纯域名（小写、去端口、去 www. 前缀），
// 使白名单里写 example.com 也能匹配 https://example.com:8443/... 这类引用。
func normalizeHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimPrefix(strings.Trim(h, "[]"), "www.")
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// neutralizeWhitelisted 把白名单域名的 src 引用替换为占位符。
func (d *Detector) neutralizeWhitelisted(content string) string {
	if len(d.domainWL) == 0 {
		return content
	}
	re := reSrc
	return re.ReplaceAllStringFunc(content, func(m string) string {
		sub := re.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		if d.domainWL[normalizeHost(sub[2])] {
			return `src="whitelisted"`
		}
		return m
	})
}

// neutralizeKnownSafe 中和第三方统计代码的 document.write(unescape(...))。
// CNZZ/友盟统计用 unescape 输出编码后的 span/script 埋点，属于正常代码，
// 与混淆挂马特征 HM-DOC-WRITE-UNESC 相同，识别到统计标识后跳过该片段。
func neutralizeKnownSafe(content string) string {
	re := reDocWriteUnesc
	return re.ReplaceAllStringFunc(content, func(m string) string {
		sub := re.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		inner := sub[1]
		if inner == "" {
			inner = sub[2]
		}
		if !strings.Contains(strings.ToLower(inner), "cnzz_stat_icon_") {
			return m
		}
		return ""
	})
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
