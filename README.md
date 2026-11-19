# webshell-guard

ASPX/ASHX 挂马与 webshell 实时监控处置工具（Go），**内置 Web 可视面板**。

监视网站脚本目录（`.aspx/.ashx/.ascx/.php/.jsp/.jspx`），实时检出两类威胁并自动处置：

1. **webshell / 一句话木马**：
   - ASP.NET：命令执行后门（`Process.Start + cmd.exe`）、Base64 写文件后门（`FromBase64String + WriteAllText`，即 Show-S6.aspx 案例同款）、动态编译后门、JScript.NET 一句话（`eval(Request.Item[..])`）、反射调用变形、`execute+request`、拆分/防替换变形写法
   - PHP：`@eval($_POST[..])` 经典一句话、`eval/assert` 执行用户输入、`eval+base64_decode` 加密后门、命令执行函数+用户输入组合、`preg_replace /e`、回调变形后门、动态文件包含、**变种**：字符串 assert 中转、变量赋值后调用、反引号执行、`extract` 变量覆盖、`system+base64_decode`、`assert(chr链)`、字符串拼接函数名、hex 混淆、`php://input` 执行、无字母数字自增马
   - JSP：`Runtime.getRuntime().exec`、`ProcessBuilder`、`ScriptEngine` 脚本引擎、动态编译 Java、`defineClass` 字节码加载、动态注册 Filter/Listener（内存马）、**变种**：反射 `Class.forName+getMethod`、Header/InputStream 传参执行、EL 表达式注入
2. **挂马注入**：外部/隐藏 `<iframe>`、外部 `<script>`、`document.write(unescape())` 混淆注入、非白名单外链域引用、**变种**：`srcdoc` 注入、`atob` 解码写入、meta refresh 跳转劫持、延迟 `setTimeout("eval(..)")`、`data:text/html;base64` 内嵌页

检出后立即**隔离**（默认，保留取证）/ **删除** / 仅告警，并通过 webhook（generic / 钉钉 / 飞书 / 企业微信）推送告警，带失败重试与频控。

## 可视面板（Web UI）与任务栏托盘

启动后自动开启，默认 `http://localhost:9090`（配置 `ui.port` 可改），三个页签：

**监控面板**：
- **实时告警流**（SSE 秒级推送，木马落地 1 秒内上屏）
- 处置记录表：时间 / 文件 / 处置方式 / 评分 / 命中规则明细
- 统计卡片：告警总数、已隔离、已删除、仅告警
- **隔离区管理**：一键恢复（放回原路径，放回的恶意文件会被再次检出）或销毁
- 运行状态：监控目录、扩展名、判恶阈值、运行时长

**任务栏托盘图标**（控制台模式运行时自动出现，服务模式无交互界面故不显示）：

- 盾牌图标常驻任务栏通知区：绿色=正常，**检出木马后变红**并显示待处理告警数
- **双击/单击图标直接打开 Web 面板**（打开后图标恢复绿色）；右键弹菜单（打开面板 / 退出程序）
- 图标为运行时纯 Go 绘制并打包 ICO（internal/tray），无需外部资源文件

**规则库页**（特征持续运营后台）：
- **自定义特征规则**：面板上直接新增/编辑/删除/启停，保存立即**热生效**（无需重启），写入 `rules_custom.yaml`（与 config.yaml 同目录，可单独覆盖更新整个特征库）
- **批量导入**：粘贴 JSON 规则数组一键导入（同 ID / 同正则自动去重），便于积累各家族小马特征包
- **在线样本测试**：粘贴疑似代码片段，立刻显示命中哪些规则、总分多少、是否会被处置，写规则不用猜
- **内置规则只读列表**：57 条内置特征全透明，命名/分值/描述一目了然
- 非法正则、分值越界等在保存时即被校验拦截

**设置页**（保存后即时生效并写回 config.yaml，注释保留）：
- 监控目录：**热更新**，新目录即刻监控、删掉的目录自动取消监控
- 脚本扩展名、处置模式（隔离/删除/仅告警）、判恶阈值
- Webhook 地址与类型（generic/钉钉/飞书/企微）
- 外链域名白名单、忽略目录、告警冷却时间
- **共享规则库同步**：启用开关、模式（raw/git）、仓库地址、特征文件、分支、周期、Token/认证头——保存即热生效并**立即试同步一次**（成功/失败直接提示；失败时缓存规则继续防护）
- 仅展示：扫描周期/防抖/大小上限等需重启生效的项

## 守护进程部署（防恶意结束）

以 Windows 服务方式常驻，自带四层防杀机制：

```bash
# 安装并启动（需管理员权限，-c 后为真实配置文件的绝对路径）
webshell-guard.exe -s install -c "E:\work\tool-go\config.yaml"

# 其他管理命令
webshell-guard.exe -s uninstall    # 卸载（自动强杀服务进程后删除）
webshell-guard.exe -s start        # 启动
webshell-guard.exe -s stop         # 停止（会被拒绝，需先卸载或强杀，强杀会自动复活）
webshell-guard.exe -s watchdog     # 看门狗手动触发（一般由计划任务每分钟调用）
```

四层防杀机制：

| 层 | 机制 | 防什么 |
|---|---|---|
| 1 | SYSTEM 权限 + 服务身份运行 | 普通进程/多数恶意代码无权结束服务进程 |
| 2 | **拒绝外部 STOP 控制码**（Accepts=0） | `sc stop` / `Stop-Service` / API ControlService 一律被 SCM 拒绝，服务根本停不掉 |
| 3 | SCM 故障恢复策略（5s→30s→60s 循环重启） | 即使管理员用任务管理器/taskkill 强杀进程，几秒内自动复活 |
| 4 | 看门狗计划任务（SYSTEM，每分钟） | 服务被禁用等极端情况也能被拉起（沙箱测试环境 schtasks 被安全策略拦截，真实服务器正常） |

卸载时会自动按 PID 强杀服务进程再删除，不会留下"杀不死"的残留。

## 多机共享规则库（Git 托管 + HTTP 拉取）

多台服务器部署时，把共享特征放进一个 Git 仓库统一管理。**git 模式下把规则 yaml 统一放仓库的 `rules/` 目录**（可按家族再分子目录），节点拉取时递归遍历该目录；旧的根目录直接放规则的布局仍兼容。

**推荐 raw 模式：节点无需安装 git**，直接 HTTP 拉取 Git 服务器的 raw 地址：

```yaml
rules_sync:
  enabled: true
  mode: raw
  repo: "https://git.example.com/team/webshell-rules/raw/branch/main"  # raw 目录前缀
  files: ["shared-rules.yaml", "php-family.yaml"]                      # 要拉取的特征文件
  interval: 300       # 拉取周期(秒)
  # token: "xxx"      # 私库认证；Gitea 私库 auth_header 可配 "Authorization: token {token}"
```

各 Git 服务器 raw 地址格式（`repo` 填对应前缀，`files` 列文件名）：

| 服务器 | repo 前缀 |
|---|---|
| Gitea / Gogs | `https://host/team/repo/raw/branch/main` |
| GitLab | `https://host/team/repo/-/raw/main` |
| GitHub | `https://raw.githubusercontent.com/user/repo/main` |

也可以 `repo` 直接填单个规则文件 URL（`files` 留空）。另有 `mode: git` 模式（整仓 clone/pull，需节点装 git）。

- 规则文件格式：`{id, kind: webshell|horse, score, desc, pattern 或 patterns[], enabled(默认true)}`；`git` 模式读仓库 `rules/` 目录（递归遍历，非规则 yaml 自动跳过），`raw` 模式由 `files` 列出文件
- **与本地规则合并注入**：同 ID 时本地 `rules_custom.yaml`（面板上改的）优先，方便单机覆盖微调
- **断源兜底**：拉取失败自动沿用上次缓存 `rules_synced.yaml`，防护不中断，恢复后自动跟上
- 面板「规则库」页显示同步状态（来源/周期/上次拉取/错误），可手动**立即同步**；`POST /api/rules {"op":"sync"}` 同效
- 变更推送到仓库后，全网节点最迟一个周期内生效

### 三类规则文件/目录的分工

| 文件/目录 | 角色 |
|---|---|
| `rules/` | 你维护规则的源，放进 Git 仓库推给各节点（本项目 `rules/shared-rules.yaml` 是空模板，往里追加即可） |
| `rules_synced.yaml` | 各节点拉取后的本地缓存（断源兜底），程序自动维护，无需手改 |
| `rules_custom.yaml` | 各节点本地面板改的规则（优先级最高），面板保存即写入 |

日常使用：

1. **新增共享规则**：编辑 `rules/*.yaml`（格式见上文），提交并推送到 Git 仓库。
2. **节点接入**：在面板「设置」页开启共享规则同步，填仓库地址/文件列表，保存后立即试同步；之后按周期自动拉取，结果缓存为 `rules_synced.yaml`。
3. **单机微调**：在面板「规则库」页增删/启停规则，写入 `rules_custom.yaml`；同 ID 时覆盖共享规则。
4. **断源兜底**：远端不可用时自动沿用 `rules_synced.yaml` 继续防护。当前为空模板时会提示「未解析到规则」，加入第一条规则后即生效。

## 使用

**推荐方式：双击 `webshell-guard.bat`**（与 exe 同目录，需管理员权限，会自动提权），菜单式管理：

```
[1] 安装守护服务   开机自启+防杀自愈，服务器/生产环境用这个
[2] 卸载守护服务   干净移除服务本体与看门狗计划任务
[3] 启动守护服务
[4] 停止守护服务   注意：服务拒绝外部停止，确需停请走 [2] 卸载
[5] 控制台模式启动 带任务栏托盘图标（绿盾/红盾、双击开面板），测试用
[6] 查看服务状态
[7] 打开监控面板   http://localhost:9090
```

首次使用会自动从 `config.example.yaml` 生成 `config.yaml`，先编辑监控目录和 webhook 再安装。

命令行方式（与 bat 等价）：

```bash
# 构建
go build -o webshell-guard.exe .

# 复制 config.example.yaml 为 config.yaml，修改 watch_dirs 与 webhook 后运行
./webshell-guard.exe -c config.yaml
```

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
internal/monitor           fsnotify 实时监控(防抖) + 周期全量兜底扫描
internal/action            处置：隔离/删除 + alert_history.jsonl 审计
internal/notify            webhook + 4 种消息模板 + 重试/频控
internal/webui             Web 面板：SSE 实时推送 + 隔离区恢复/销毁 + 规则库管理（页面 embed 内嵌）
docs/需求分析.md            完整需求分析
config.example.yaml        配置样例（含全部配置项注释）
testenv/                   端到端测试环境（含 webhook 接收器）
```

## 关键机制

- **评分制判恶**（阈值默认 6）：强特征单条即可判死，弱特征需组合命中，降低误报。
- **基线学习**：干净文件哈希自动入基线；基线文件被改且命中规则 → 高可信告警（`baseline=true`）。
- **防抖 500ms**：等文件写完再检测；超过 5MB 的大文件留给周期扫描。
- **白名单**：外链域名白名单（CDN）+ 文件 SHA256 白名单。
- **审计**：每次处置写入 `alert_history.jsonl`，webhook 挂了也不丢记录。
