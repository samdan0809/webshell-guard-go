# webshell-guard

ASPX/ASHX/JSP/PHP 网站脚本目录的**挂马与 webshell 实时监控处置工具**（Go 开发，单文件 exe），内置 Web 可视面板与任务栏托盘。

- **实时检测**：fsnotify 监控 + 周期全量兜底扫描，木马落地 1 秒内告警
- **评分制判恶**：强特征单条判死、弱特征组合命中，降低误报（内置 64 条规则）
- **自动处置**：隔离（默认，保留取证）/ 删除 / 仅告警，webhook 推送（钉钉/飞书/企业微信/generic）
- **可视化运营**：规则增删改热生效、在线样本测试、隔离区管理、AI 复核与误报自学习
- **防杀自愈**：Windows 服务四层防杀 + 看门狗，支持多机共享规则库与程序自升级

## 目录

- [快速开始](#快速开始)
- [检测能力](#检测能力)
- [Web 可视面板与任务栏托盘](#web-可视面板与任务栏托盘)
- [守护进程部署（防恶意结束）](#守护进程部署防恶意结束)
- [多机共享规则库](#多机共享规则库)
- [AI 复核（误报自学习）](#ai-复核误报自学习)
- [程序自升级](#程序自升级)
- [发布新版本](#发布新版本)
- [关键机制](#关键机制)
- [目录结构](#目录结构)

## 快速开始

**推荐：双击 `webshell-guard.bat`**（与 exe 同目录，自动请求管理员权限），菜单式管理：

```
[1] 安装守护服务   开机自启+防杀自愈，服务器/生产环境用这个
[2] 卸载守护服务   干净移除服务本体与看门狗计划任务
[3] 启动守护服务
[4] 停止守护服务   注意：服务拒绝外部停止，确需停请走 [2] 卸载
[5] 控制台模式启动 带任务栏托盘图标（绿盾/红盾、双击开面板），测试用
[6] 查看服务状态
[7] 打开监控面板   http://localhost:9090
[8] 检查更新升级   从远端清单下载新版并自动重启
```

首次运行会自动从 `config.example.yaml` 生成 `config.yaml`，**先编辑监控目录 `watch_dirs` 和 webhook 再安装服务**。

命令行方式（与 bat 等价）：

```bash
build.bat v1.0.0                     # 构建（带版本号，供自升级比对）
./webshell-guard.exe -c config.yaml  # 控制台模式运行
webshell-guard.exe -v                # 查看当前版本
```

## 检测能力

监视 `.aspx/.ashx/.ascx/.php/.jsp/.jspx` 文件，实时检出两类威胁。判恶采用评分制（阈值默认 6）：强特征单条即可判死，弱特征需组合命中，降低误报。

**1. webshell / 一句话木马**

| 语言 | 检出特征（示例） |
|---|---|
| ASP.NET | `Process.Start + cmd.exe` 命令执行后门、`FromBase64String + WriteAllText` 写文件后门（Show-S6.aspx 案例同款）、动态编译后门、JScript.NET 一句话（`eval(Request.Item[..])`）、反射调用变形、`execute+request`、拆分/防替换变形 |
| PHP | `@eval($_POST[..])` 经典一句话、`eval/assert` 执行用户输入、`eval+base64_decode` 加密后门、命令执行函数+用户输入组合、`preg_replace /e`、回调变形后门、动态文件包含；变种：assert 中转、变量赋值后调用、反引号执行、`extract` 变量覆盖、`system+base64_decode`、`assert(chr链)`、字符串拼接函数名、hex 混淆、`php://input` 执行、无字母数字自增马 |
| JSP | `Runtime.getRuntime().exec`、`ProcessBuilder`、`ScriptEngine` 脚本引擎、动态编译 Java、`defineClass` 字节码加载、动态注册 Filter/Listener（内存马）；变种：反射 `Class.forName+getMethod`、Header/InputStream 传参执行、EL 表达式注入 |

**2. 挂马注入**

外部/隐藏 `<iframe>`、外部 `<script>`、`document.write(unescape())` 混淆注入、非白名单外链域引用；变种：`srcdoc` 注入、`atob` 解码写入、meta refresh 跳转劫持、延迟 `setTimeout("eval(..)")`、`data:text/html;base64` 内嵌页。

**3. 误报治理**

- 面板可增删改规则并**热生效**（无需重启/重编译），支持关键字组合规则（不想写正则时逐行填关键字，全部出现才计分）
- 外链域名白名单（CDN）+ 文件 SHA256 白名单
- AI 复核（见下文）：风险字符送审，SAFE 自动永久加白

## Web 可视面板与任务栏托盘

启动后自动开启，默认 `http://localhost:9090`（`ui.port` 可改）。面板走 Basic Auth：登录框**用户名任意、密码填 `ui.token`**；未配置时每次启动随机生成并打印到日志（服务模式见 exe 同目录 `service.log`）。API 同样需要认证，避免本机任意进程操作隔离区/规则。

### 监控面板页

- **实时告警流**：SSE 秒级推送，木马落地 1 秒内上屏
- 处置记录表：时间 / 文件 / 处置方式 / 评分 / 命中规则明细
- 统计卡片：告警总数、已隔离、已删除、仅告警
- **隔离区管理**：一键恢复（放回原路径并按内容哈希自动加白）或销毁
- 隔离文件名追加 `.blocked` 后缀，即使隔离目录误配在网站目录下也不会被 Web 服务器当脚本执行
- 运行状态：监控目录、扩展名、判恶阈值、运行时长

### 规则库页

- **自定义特征规则**：面板直接新增/编辑/删除/启停，保存立即热生效，写入 `rules_custom.yaml`
- **快速模板**：一键套用常用骨架（PHP 一句话/命令执行、JSP exec、ASPX 后门、挂马外链/跳转）
- **关键字组合**：每行一个关键字，全部出现才计分（自动转义、忽略大小写）
- **批量导入**：粘贴 JSON 或 YAML 均可，也可选 `.yaml/.yml/.json` 文件导入；同 ID / 同正则自动去重
- **在线样本测试**：粘贴疑似代码片段，立刻显示命中规则、总分、是否会被处置
- **内置规则（64 条）**：首次启动生成可编辑副本 `rules_builtin.yaml`；改正则/分值/停用均无需重编译重启
- 保存时即校验非法正则、分值越界

### 设置页（保存后即时生效并写回 config.yaml，注释保留）

- 监控目录**热更新**：新目录即刻监控、删掉的目录自动取消监控
- 脚本扩展名、处置模式、判恶阈值
- Webhook 地址与类型（generic/钉钉/飞书/企微）
- 外链域名白名单、忽略目录、告警冷却时间
- **共享规则库同步**：保存即热生效并立即试同步一次（失败时缓存规则继续防护）
- 仅展示：扫描周期/防抖/大小上限等需重启生效的项

### 任务栏托盘图标（控制台模式运行时显示，服务模式无）

- 盾牌常驻通知区：绿色=正常，**检出木马后变红**并显示待处理告警数
- 双击/单击图标直接打开 Web 面板（打开后恢复绿色）；右键菜单：打开面板 / 检查更新 / 退出
- 图标为运行时纯 Go 绘制并打包 ICO（`internal/tray`），无需外部资源文件

## 守护进程部署（防恶意结束）

以 Windows 服务方式常驻，四层防杀：

| 层 | 机制 | 防什么 |
|---|---|---|
| 1 | SYSTEM 权限 + 服务身份运行 | 普通进程/多数恶意代码无权结束服务进程 |
| 2 | **拒绝外部 STOP 控制码**（Accepts=0） | `sc stop` / `Stop-Service` / API ControlService 一律被 SCM 拒绝 |
| 3 | SCM 故障恢复策略（5s→30s→60s 循环重启） | 即使管理员用任务管理器/taskkill 强杀，几秒内自动复活 |
| 4 | 看门狗计划任务（SYSTEM，每分钟） | 服务被禁用等极端情况也能被拉起 |

```bash
# 安装并启动（需管理员权限，-c 后为真实配置文件的绝对路径）
webshell-guard.exe -s install -c "E:\work\tool-go\config.yaml"

# 其他管理命令
webshell-guard.exe -s uninstall    # 卸载（自动强杀服务进程后删除）
webshell-guard.exe -s start        # 启动
webshell-guard.exe -s stop         # 停止（会被拒绝，需先卸载或强杀，强杀会自动复活）
webshell-guard.exe -s watchdog     # 看门狗手动触发（一般由计划任务每分钟调用）
```

卸载时自动按 PID 强杀服务进程再删除，不留"杀不死"的残留。

## 多机共享规则库

多台服务器部署时，把共享特征放进一个 Git 仓库统一管理。**git 模式下规则 yaml 统一放仓库 `rules/` 目录**（可按家族分子目录），节点递归遍历拉取；旧的根目录布局仍兼容。

**推荐 raw 模式：节点无需安装 git**，直接 HTTP 拉取：

```yaml
rules_sync:
  enabled: true
  mode: raw
  repo: "https://git.example.com/team/webshell-rules/raw/branch/main"  # raw 目录前缀
  files: ["shared-rules.yaml", "php-family.yaml"]                      # 要拉取的特征文件
  interval: 300       # 拉取周期(秒)
  # token: "xxx"      # 私库认证；Gitea 私库 auth_header 可配 "Authorization: token {token}"
```

| Git 服务器 | repo 前缀 |
|---|---|
| Gitea / Gogs | `https://host/team/repo/raw/branch/main` |
| GitLab | `https://host/team/repo/-/raw/main` |
| GitHub | `https://raw.githubusercontent.com/user/repo/main` |

也可以 `repo` 直接填单个规则文件 URL（`files` 留空）。另有 `mode: git` 模式（整仓 clone/pull，需节点装 git）。

**规则文件格式**：`{id, kind: webshell|horse, score, desc, pattern 或 patterns[] 或 keywords[], enabled(默认true)}`；`keywords` 为纯文本关键字组合（全部出现才计分）。

**运行规则来源与优先级**（同 ID 时后者覆盖前者）：

| 文件/目录 | 角色 |
|---|---|
| `rules/` | 你维护的共享规则源，推送到 Git 仓库（本项目 `rules/shared-rules.yaml` 是空模板） |
| `rules_synced.yaml` | 节点拉取后的本地缓存（断源兜底），程序自动维护 |
| `rules_custom.yaml` | 各节点面板上改的规则，**优先级最高** |
| `rules_builtin.yaml` | 内置规则可编辑副本（改正则/分值/停用） |

日常使用：

1. **新增共享规则**：编辑 `rules/*.yaml`，提交推送到 Git 仓库，全网节点最迟一个周期内生效
2. **节点接入**：面板「设置」页开启共享规则同步，填仓库地址/文件列表，保存即试同步；结果缓存为 `rules_synced.yaml`
3. **单机微调**：面板「规则库」页增删/启停，写入 `rules_custom.yaml`，同 ID 覆盖共享规则
4. **断源兜底**：远端不可用时自动沿用 `rules_synced.yaml` 继续防护（空模板会提示「未解析到规则」，加入第一条规则后即生效）
5. 面板「规则库」页显示同步状态，可手动立即同步；`POST /api/rules {"op":"sync"}` 同效

## AI 复核（误报自学习）

命中「风险字符」的文件会**先送 AI 判定**（与规则得分无关，规则没报也会送审），AI 固定回答 `SAFE` / `MALICIOUS`：

- `SAFE` → 按内容 SHA256 **永久加白**（写入 `ai_whitelist.json`），此后同内容不再检测、不再请求 AI
- `MALICIOUS` → 按恶意处置（原本分数不足阈值的也会拉到阈值强制处置）
- 请求失败 / 回答无法识别 → **沿用规则原判定**，AI 挂了不影响防护
- 隔离区「恢复」也会按内容哈希自动加白（来源 `manual-restore`），避免刚放回去又被同一规则隔离
- 面板「设置」页可查看/移除白名单，「测试 AI 接口」按钮做连通性探测（`POST /api/aitest` 同效）

配置示例（`config.yaml`，改完需重启）：

```yaml
ai_judge:
  enabled: true
  type: chat                        # chat(自建接口,默认) | openai(OpenAI 兼容)
  timeout: 20                       # 单次请求超时(秒)
  whitelist_file: "./ai_whitelist.json"
  keywords: []                      # 风险字符(正则)，留空用内置默认

  # ── type: chat —— 自建 chat.ashx ──
  url: "http://192.168.0.132:8787/api/open/chat.ashx"
  app_key: "your_app_key"           # 自建接口的 APPKEY（勿公开提交）；key = md5(时间戳 + app_key)
  date_unit: ms                     # date 参数：ms(毫秒) | s(秒) | datetime(yyyyMMddHHmmss)
  key_order: date_first             # date_first(时间戳+APPKEY) | appkey_first(APPKEY+时间戳)
  key_upper: false                  # MD5 是否转大写

  # ── type: openai —— 标准 OpenAI 兼容接口 ──
  # url: "https://api.openai.com/v1/chat/completions"   # 中转站/本地大模型同格式
  # app_key: "sk-xxxxxxxx"           # 作为 Authorization: Bearer <app_key>
  # model: "gpt-4o-mini"             # 必填：gpt-4o-mini / deepseek-chat / qwen-plus / 本地模型名
```

**触发时机**：文件内容命中风险字符才请求 AI。默认风险字符（`keywords` 可覆盖）：`ProcessStartInfo`、`Process`、`.WriteAllText`、`.WriteAllBytes`、`FromBase64String`、`GetEnvironmentVariable`、`comspec`、`powershell`、`cmd.exe`。

**行为细节**：

- 同一 SHA256 一次运行内只请求一次；已加白的不再请求
- 提示词内置判定标准（真实执行链路/用户输入拼接 → MALICIOUS；仅构造对象未执行、固定参数业务代码 → SAFE），AI 只回一个词
- `chat` 模式：`date` 与服务器时间差不能超 3 分钟（NTP 同步）；`content` 走 POST 表单（避开 IIS `maxQueryString` 限制）；签名同时以 `sign`/`key` 两个参数名发送
- `openai` 模式：`model` 必填；提示词拆分为 system + user 两条消息
- 送审片段最长 1500 字节，超长截断并标注
- 全量扫描时串行送审，约 0.5~6s/文件，文件多时耐心等「扫描完成」日志

## 程序自升级

支持检查远端新版本、下载替换 exe 并自动重启生效，四个入口：

1. **命令行手动升级**：`webshell-guard.exe -update -c config.yaml`
2. **Web 面板**：顶部「检查更新」→ 发现新版后点「升级到新版本」
3. **托盘菜单**：控制台模式右键「检查更新」
4. **定时自动检查**：`update.enabled=true` 后按周期检查；`auto_apply=true` 时自动升级重启（默认仅提示，人工确认）

配置示例（`config.yaml`）：

```yaml
update:
  enabled: true
  auto_apply: false    # true: 自动升级; false: 仅面板/托盘提示
  url: "https://gitcode.com/Kealy/webshell-guard-go/releases/download/latest/manifest.json"
  interval: 3600       # 检查周期(秒)
  token: ""
  auth_header: ""      # 私有下载源时的认证头, 支持 {token} 占位
```

升级清单（manifest.json）格式——`url` 指向新版 exe，`sha256` 强烈建议填写（不符直接丢弃，防篡改/下载不完整）：

```json
{"version":"v1.0.2","url":"https://gitcode.com/Kealy/webshell-guard-go/releases/download/latest/webshell-guard.exe","sha256":"<64位哈希>","notes":"修复xxx"}
```

**替换原理**（Windows 运行中的 exe 不能覆盖但可重命名）：当前 exe 改名 `.old` 备份 → 新版落盘原路径 → 进程退出。服务模式以退出码 2 触发 SCM 恢复策略数秒内拉起新版本；控制台模式自动拉起新进程。版本号按点分数字比较，`dev` 版本总会被正式版本升级。

## 发布新版本

发布源为**双平台**：GitCode（节点升级源，国内可达）+ GitHub（镜像备份），tag 均按真实版本号（如 `v1.0.2`）。

**第 1 步：提交并双平台推送**

```bash
git add -A && git commit -m "..."
git push origin main        # origin = GitHub
git push gitcode main       # gitcode = GitCode（URL 已内嵌令牌，免密）
git push origin vX.Y.Z && git push gitcode vX.Y.Z   # 推标签
```

**第 2 步：一键构建发布包**

```bash
release\release.bat vX.Y.Z
```

自动完成：注入版本号编译 → 计算 SHA256 → 生成 `manifest.json`，产物在 `release\dist\`：

| 文件 | 作用 |
|---|---|
| `webshell-guard.exe` | 新版本程序（Release 附件） |
| `manifest.json` | 升级清单，url 固定指向 gitcode 的 `releases/download/latest/` 别名 |
| `webshell-guard.exe.sha256` | 哈希校验文件（人工核对用） |

**第 3 步：两个平台各建一个 Release**（标签填 `vX.Y.Z`，与构建版本号一致），上传 `release\dist\` 下的 3 个文件：

- GitCode：<https://gitcode.com/Kealy/webshell-guard-go/releases>
- GitHub：<https://github.com/samdan0809/webshell-guard-go/releases/new>，或 gh CLI：

```bash
gh release create vX.Y.Z release\dist\webshell-guard.exe release\dist\manifest.json release\dist\webshell-guard.exe.sha256 --title "vX.Y.Z" --notes "变更说明"
```

**已部署节点无需改任何配置**：`update.url` 固定为

```
https://gitcode.com/Kealy/webshell-guard-go/releases/download/latest/manifest.json
```

gitcode 的 `latest` 下载别名自动跟随最新发行版，发布后最迟一个 `interval`（默认 1 小时）内节点即会检查到新版本。

> 注意：每次构建的 `BuildDate` 时间戳不同，同一版本重复构建会得到不同 SHA256——**上传附件时必须让 manifest.json 的 sha256 与实际挂着的 exe 一致**，建议每次 `release.bat` 构建后立即把当次 3 个文件一起上传。

## 快速自检

```bash
go test ./...
```

## 目录结构

```
main.go                    入口：装配、日志双写、信号处理、Web UI 启动
internal/config            配置加载/校验（yaml）
internal/detector          规则库 + 评分检测 + SHA256 基线
internal/rules             自定义规则库：持久化/校验/导入/热加载（rules_custom.yaml）
internal/monitor           fsnotify 实时监控(防抖) + 周期全量兜底扫描 + 立即扫描
internal/aijudge           AI 复核(chat/openai) + SHA256 白名单持久化
internal/action            处置：隔离/删除 + alert_history.jsonl 审计
internal/notify            webhook + 4 种消息模板 + 重试/频控
internal/updater           程序自升级：清单拉取/版本比对/下载校验/原地替换
internal/webui             Web 面板：SSE 实时推送 + 隔离区恢复/销毁 + 规则库管理（页面 embed 内嵌）
docs/需求分析.md            完整需求分析
config.example.yaml        配置样例（含全部配置项注释）
release/release.bat        发布构建脚本（版本注入 + SHA256 + manifest）
testenv/                   端到端测试环境（含 webhook 接收器）
```

## 关键机制

- **评分制判恶**（阈值默认 6）：强特征单条即可判死，弱特征需组合命中，降低误报
- **基线学习**：干净文件哈希自动入基线；基线文件被改且命中规则 → 高可信告警（`baseline=true`）
- **防抖 500ms**：等文件写完再检测；超过 5MB 的大文件留给周期扫描
- **白名单**：外链域名白名单（CDN）+ 文件 SHA256 白名单
- **审计**：每次处置写入 `alert_history.jsonl`，webhook 挂了也不丢记录
