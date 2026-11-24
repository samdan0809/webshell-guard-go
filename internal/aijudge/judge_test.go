package aijudge

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseVerdict(t *testing.T) {
	cases := map[string]Verdict{
		"SAFE":         Safe,
		"safe.":        Safe,
		" MALICIOUS ":  Malicious,
		"结论：SAFE":      Safe,
		"结论：MALICIOUS": Malicious,
		"NOT SAFE":     Malicious,
		"这段代码是恶意后门":    Malicious,
		"正常业务代码，安全":    Safe,
	}
	for in, want := range cases {
		got, err := parseVerdict(in)
		if err != nil {
			t.Fatalf("%q 解析失败: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q => %v, want %v", in, got, want)
		}
	}
	if _, err := parseVerdict("我不知道"); err == nil {
		t.Fatal("无法识别的回答应报错")
	}
}

func TestAskBuildsSignedQuery(t *testing.T) {
	var gotQuery map[string]string
	var gotForm map[string]string
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		q := r.URL.Query()
		gotQuery = map[string]string{
			"mode": q.Get("mode"), "date": q.Get("date"),
			"key": q.Get("key"), "sign": q.Get("sign"),
		}
		if err := r.ParseForm(); err == nil {
			gotForm = map[string]string{"content": r.Form.Get("content")}
		}
		_, _ = w.Write([]byte(`{"code":0,"data":"SAFE"}`))
	}))
	defer srv.Close()

	j, err := New(Config{Enabled: true, URL: srv.URL + "/api/open/chat.ashx", AppKey: "dang888"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := j.ask(context.Background(), "判定这段代码", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Answer != "SAFE" {
		t.Fatalf("JSON 回答未提取到 data 字段: %q", resp.Answer)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("content 应走 POST 表单, 实际 %s", gotMethod)
	}
	ts, err := strconv.ParseInt(gotQuery["date"], 10, 64)
	if err != nil {
		t.Fatalf("date 不是时间戳: %q", gotQuery["date"])
	}
	sum := md5.Sum([]byte(gotQuery["date"] + "dang888"))
	want := hex.EncodeToString(sum[:])
	// 服务端读 sign，文档里叫 key，两个都要带且一致
	if gotQuery["sign"] != want || gotQuery["key"] != want {
		t.Fatalf("签名应为 md5(时间戳+APPKEY)=%s, 实际 sign=%s key=%s", want, gotQuery["sign"], gotQuery["key"])
	}
	if len(gotQuery["date"]) != 13 {
		t.Fatalf("默认 date 应为毫秒时间戳, 实际 %q", gotQuery["date"])
	}
	if gotQuery["mode"] != "message" {
		t.Fatalf("mode=%q", gotQuery["mode"])
	}
	if gotForm["content"] != "判定这段代码" {
		t.Fatalf("content 应在 POST 表单里, 实际 %q", gotForm["content"])
	}
	if d := time.Now().UnixMilli() - ts; d < -5000 || d > 5000 {
		t.Fatalf("date(毫秒) 与当前时间偏差过大: %d", d)
	}
}

func TestBuildPromptFixedVocabulary(t *testing.T) {
	p := buildPrompt(`E:\site\a.aspx`, `var x = Convert.FromBase64String("eA==");`, 1500)
	for _, want := range []string{"只输出一个词", TokenSafe, TokenMalicious, `E:\site\a.aspx`, "FromBase64String"} {
		if !strings.Contains(p, want) {
			t.Fatalf("提示词缺少 %q:\n%s", want, p)
		}
	}
	// 超长代码按字节截断，且不出现半个汉字
	long := strings.Repeat("木马", 2000)
	cut := snippet(long, 101)
	if len(cut) > 101+len("\n...[代码过长已截断]") {
		t.Fatalf("截断后仍过长: %d", len(cut))
	}
	if strings.ContainsRune(cut, '\uFFFD') {
		t.Fatal("截断把汉字切坏了")
	}
}

func TestReviewSafePersistsWhitelist(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte("SAFE"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := filepath.Join(dir, "ai_whitelist.json")
	j, err := New(Config{Enabled: true, URL: srv.URL, AppKey: "dang888", WhitelistFile: wl})
	if err != nil {
		t.Fatal(err)
	}
	content := `var a=System.Convert.FromBase64String("xxx");`
	if !j.HasRisk(content) {
		t.Fatal("风险字符未命中")
	}
	v, err := j.Review(context.Background(), `E:\site\a.aspx`, content, "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if v != Safe {
		t.Fatalf("裁定=%v", v)
	}
	if !j.IsWhitelisted("abc123") {
		t.Fatal("SAFE 后应加白")
	}

	// 同样的内容再判定：命中缓存，不再发请求
	if _, err := j.Review(context.Background(), `E:\site\a.aspx`, content, "abc123"); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("缓存未生效，请求了 %d 次", n)
	}

	// 重新加载（模拟重启）：白名单必须还在，且哈希统一小写
	j2, err := New(Config{Enabled: true, URL: srv.URL, AppKey: "dang888", WhitelistFile: wl})
	if err != nil {
		t.Fatal(err)
	}
	if !j2.IsWhitelisted("ABC123") {
		t.Fatal("白名单未持久化（或哈希未统一小写）")
	}
	items := j2.Whitelist()
	if len(items) != 1 || items[0].Path != `E:\site\a.aspx` {
		t.Fatalf("白名单条目异常: %+v", items)
	}
	if err := j2.RemoveWhitelist("abc123"); err != nil {
		t.Fatal(err)
	}
	if j2.IsWhitelisted("abc123") {
		t.Fatal("移除白名单未生效")
	}
}

func TestAddWhitelistPersists(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "ai_whitelist.json")
	j, err := New(Config{Enabled: false, WhitelistFile: wl})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AddWhitelist(`E:\site\a.aspx`, "ABC123", "manual-restore"); err != nil {
		t.Fatal(err)
	}
	if !j.IsWhitelisted("abc123") {
		t.Fatal("手动加白未生效（哈希需统一小写）")
	}

	j2, err := New(Config{Enabled: false, WhitelistFile: wl})
	if err != nil {
		t.Fatal(err)
	}
	items := j2.Whitelist()
	if len(items) != 1 || items[0].Reason != "manual-restore" || items[0].Path != `E:\site\a.aspx` {
		t.Fatalf("白名单未持久化: %+v", items)
	}
	if err := j2.AddWhitelist("", "", ""); err == nil {
		t.Fatal("空哈希应报错")
	}
}

func TestReviewMaliciousNotWhitelisted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("MALICIOUS"))
	}))
	defer srv.Close()

	j, err := New(Config{Enabled: true, URL: srv.URL, AppKey: "dang888",
		WhitelistFile: filepath.Join(t.TempDir(), "wl.json")})
	if err != nil {
		t.Fatal(err)
	}
	v, err := j.Review(context.Background(), `E:\site\b.aspx`, `powershell.exe -c whoami`, "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if v != Malicious {
		t.Fatalf("裁定=%v", v)
	}
	if j.IsWhitelisted("deadbeef") {
		t.Fatal("MALICIOUS 不应加白")
	}
}

func TestTestEndpointProbe(t *testing.T) {
	var gotPrompt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			gotPrompt = r.Form.Get("content")
		}
		_, _ = w.Write([]byte(`{"data":"SAFE"}`))
	}))
	defer srv.Close()

	j, err := New(Config{Enabled: true, URL: srv.URL, AppKey: "dang888"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := j.Test(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Verdict != Safe {
		t.Fatalf("探测结果异常: %+v", res)
	}
	if res.Answer != "SAFE" || res.ElapsedMS < 0 {
		t.Fatalf("未返回原始回答/耗时: %+v", res)
	}
	if gotPrompt != TestPrompt {
		t.Fatalf("探测提示词应固定为 %q, 实际 %q", TestPrompt, gotPrompt)
	}
	// 探测不应污染白名单
	if len(j.Whitelist()) != 0 {
		t.Fatal("连通性测试不应写入白名单")
	}
}

func TestTestEndpointErrors(t *testing.T) {
	// 未启用
	off, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := off.Test(context.Background(), nil); err == nil {
		t.Fatal("未启用时应报错")
	}

	// HTTP 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	j, err := New(Config{Enabled: true, URL: srv.URL, AppKey: "dang888"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Test(context.Background(), nil); err == nil {
		t.Fatal("接口 500 时应报错")
	}

	// 回答不是固定词汇
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("今天天气不错"))
	}))
	defer srv2.Close()
	j2, err := New(Config{Enabled: true, URL: srv2.URL, AppKey: "dang888"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := j2.Test(context.Background(), nil)
	if err == nil {
		t.Fatal("非固定词汇回答应报错")
	}
	if res.Answer != "今天天气不错" || res.OK {
		t.Fatalf("错误结果应带上原始回答: %+v", res)
	}
	if res.Raw != "今天天气不错" || res.Status != http.StatusOK {
		t.Fatalf("错误结果应带上响应原文与状态码: %+v", res)
	}
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestSignParamsVariants(t *testing.T) {
	j, err := New(Config{Enabled: true, URL: "http://127.0.0.1:1", AppKey: "dang888"})
	if err != nil {
		t.Fatal(err)
	}
	// 默认：毫秒时间戳 + 时间戳在前 + 小写
	date, key := j.signParams(nil)
	if len(date) != 13 || key != md5hex(date+"dang888") {
		t.Fatalf("默认签名异常: date=%q key=%q", date, key)
	}

	// 覆盖为秒级 + 大写
	upper := true
	date, key = j.signParams(&SignOverride{DateUnit: "s", KeyUpper: &upper})
	if len(date) != 10 || key != strings.ToUpper(md5hex(date+"dang888")) {
		t.Fatalf("秒/大写签名异常: date=%q key=%q", date, key)
	}

	// yyyyMMddHHmmss + APPKEY 在前
	date, key = j.signParams(&SignOverride{DateUnit: "datetime", KeyOrder: "appkey_first"})
	if len(date) != 14 || key != md5hex("dang888"+date) {
		t.Fatalf("datetime/反序签名异常: date=%q key=%q", date, key)
	}
}

func TestOpenAIType(t *testing.T) {
	var auth, model, sysMsg, userMsg string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		var body struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			model = body.Model
			for _, m := range body.Messages {
				switch m.Role {
				case "system":
					sysMsg = m.Content
				default:
					userMsg = m.Content
				}
			}
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"MALICIOUS"}}]}`))
	}))
	defer srv.Close()

	j, err := New(Config{Enabled: true, Type: "openai", URL: srv.URL, AppKey: "dang888", Model: "gpt-4o-mini"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := j.Review(context.Background(), `E:\site\a.aspx`, `Process.Start("cmd.exe")`, "oai1")
	if err != nil {
		t.Fatal(err)
	}
	if v != Malicious {
		t.Fatalf("裁定=%v", v)
	}
	if auth != "Bearer dang888" {
		t.Fatalf("app_key 应作为 Bearer key, 实际 %q", auth)
	}
	if model != "gpt-4o-mini" {
		t.Fatalf("model=%q", model)
	}
	if !strings.Contains(sysMsg, TokenMalicious) {
		t.Fatal("system 消息应包含判定标准")
	}
	if !strings.Contains(userMsg, `E:\site\a.aspx`) {
		t.Fatal("user 消息应包含文件路径与代码")
	}
	if j.IsWhitelisted("oai1") {
		t.Fatal("MALICIOUS 不应加白")
	}
}

func TestOpenAIRequiresModel(t *testing.T) {
	if _, err := New(Config{Enabled: true, Type: "openai", URL: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("openai 模式未配置 model 应报错")
	}
	if _, err := New(Config{Enabled: true, Type: "bad", URL: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("非法 type 应报错")
	}
}

func TestCustomKeywords(t *testing.T) {
	j, err := New(Config{Enabled: true, URL: "http://127.0.0.1:1", Keywords: []string{"Request\\.Item", "eval"}})
	if err != nil {
		t.Fatal(err)
	}
	if !j.HasRisk(`eval(request.item["z"])`) {
		t.Fatal("自定义风险字符（忽略大小写）未命中")
	}
	if j.HasRisk("Process.Start") {
		t.Fatal("配置了自定义关键字后不应再用默认关键字")
	}
}
