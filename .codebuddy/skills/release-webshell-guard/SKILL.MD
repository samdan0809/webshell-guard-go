---
name: release-webshell-guard
description: 本项目 webshell-guard-go 的完整发版流程：跑测试 → git 提交/打标签/推送 → release.bat 构建带版本号产物 → 校验版本 → 发布 GitHub Release。当用户要求"发布"、"发版"、"出 release"、"编译 vX.Y.Z"、"git 发布"时使用本 skill。
---

# Release Webshell Guard

## Overview

执行本项目从代码提交到 GitCode Release 的完整发布动作。版本号通过 ldflags 注入（`internal/version/version.go`，默认 "dev"），无需改源码。发布产物为 `release\dist\` 下的 `webshell-guard.exe` + `.sha256` + `manifest.json`（自升级清单）。

## 发布流程（按序执行）

### 1. 发布前检查

```powershell
go test ./...        # 全部测试必须通过
go build ./...       # 编译验证
```

测试或编译失败则停止发布，先修复。

### 2. Git 提交与推送

- `git status --short` 查看改动；删除误生成的杂物文件（如内容只有 "webshell-guard" 的 `query` 文件，多为命令重定向笔误产物），不要提交杂物。
- 提交信息用中文，参考既有风格（`fix:` / `feat:` 前缀 + 简述）。
- 确认版本号：`git tag --sort=-v:refname` 查看已有标签，新版本号递增（v1.0.1 → v1.0.2 …）。

```powershell
git add <改动文件>
git commit -m "<中文提交信息>"
git tag vX.Y.Z
# 默认双平台推送: origin=github, gitcode=国内镜像
git push origin main
git push origin vX.Y.Z
git push gitcode main
git push gitcode vX.Y.Z
```

### 3. 构建发布产物

```powershell
cmd /c "release\release.bat vX.Y.Z"
```

产出（`release\dist\`）：
- `webshell-guard.exe` — ldflags 注入 `Version=vX.Y.Z` 与 `BuildDate`
- `webshell-guard.exe.sha256`
- `manifest.json` — 自升级清单，`url` 指向 gitcode latest 发行版的 exe 地址

### 4. 校验版本注入

```powershell
go version -m release\dist\webshell-guard.exe | Select-String "Version|BuildDate"
```

输出必须含 `-X webshell-guard/internal/version.Version=vX.Y.Z`。

### 5. 发布产物到 GitCode + GitHub（双平台，都传同 3 个文件）

`release\dist` 下 3 个文件：`webshell-guard.exe`、`manifest.json`、`webshell-guard.exe.sha256`。manifest 的 url 固定指向 gitcode（节点升级源，国内可达），两个平台传**同一份**。

- **GitCode**（节点升级源）：https://gitcode.com/Kealy/webshell-guard-go/releases
  - 新建发行版，选标签 `vX.Y.Z`，上传 3 个文件。
  - 下载别名 `releases/download/latest/<文件名>` 自动跟随 `release_status=latest` 的最新发行版，节点配置无需变更。
  - 无 gh CLI 等价物，网页上传。
- **GitHub**（镜像备份）：https://github.com/samdan0809/webshell-guard-go/releases/new
  - 本机通常未装 gh CLI，先 `gh --version` 探测：
    ```powershell
    gh release create vX.Y.Z "release\dist\webshell-guard.exe" "release\dist\manifest.json" "release\dist\webshell-guard.exe.sha256" --title "vX.Y.Z" --notes "<本次改动简述>"
    ```
  - 无 gh 则网页上传同 3 个文件。

## GitCode 访问令牌与 API

- 令牌已注册为**用户级环境变量 `GITCODE_TOKEN`**（HKCU\Environment），新开的进程可直接读 `$env:GITCODE_TOKEN`；**严禁把令牌明文写进任何仓库内文件**。
- API 基址：`https://api.gitcode.com/api/v5`（注意是 api.gitcode.com，不是 gitcode.com），鉴权用 `?access_token=<令牌>` 查询参数。
- 验证令牌：`GET /user?access_token=$env:GITCODE_TOKEN`，返回 login=Kealy 即有效。
- 列出发行版（含附件 id/size/digest sha256）：
  ```powershell
  curl.exe -s "https://api.gitcode.com/api/v5/repos/Kealy/webshell-guard-go/releases?access_token=$env:GITCODE_TOKEN"
  ```
- **重要发现**：gitcode 支持 `releases/download/latest/<文件名>` 别名，自动跟随 `release_status=latest` 的发行版。所以发行版可以按真实版本打标签（v1.0.2…），下载地址保持固定，无需覆盖上传。
- **GitCode 推送认证**：remote `gitcode` 的 URL 已内嵌访问令牌（存本地 .git/config，不随仓库提交），`git push gitcode` 免密；GitCode git 推送不认账号密码，只认令牌。
- **镜像仓库限制（已解除）**：GitCode 导入生成的仓库是只读镜像仓库，git push 会被拒（报 "repository is an image repository"）；**2026-11-24 已转为普通仓库**，push 与 API 正常。若将来重建/重新导入仓库遇到该报错，需先在 GitCode 仓库设置里转为普通仓库。
- 附件上传 API（Gitee v5 风格 attach_files）尚未实测，当前发布仍以网页上传为准；若要自动化，先小范围验证 POST 端点再固化到本 skill。

## 注意事项

- **运行中的服务**：本机可能装有名为 `webshell-guard` 的 Windows 服务，exe 即工程根目录的 `webshell-guard.exe`。`release.bat` 输出到 `release\dist\`，不会触碰运行中的 exe；但若要**替换根目录 exe 更新本机服务**，须先 `sc query webshell-guard` 确认状态，替换会直接影响运行中的防护服务。
- **PowerShell 环境**：命令在 PowerShell 下执行，多条命令用 `;` 分隔（`&` 会报错）；传给内层 PowerShell 的字符串中 `$` 会被外层吞掉，需要 `$` 的逻辑写成临时 .ps1 脚本再执行。
- **标签与版本必须一致**：manifest.json 中的 version 与 git tag 必须同为 `vX.Y.Z` 格式，否则节点自升级比对会失败（updater 会 trim 前缀 `v` 后做语义比较）。两个平台的发行版都按真实版本打标签；gitcode 的 `releases/download/latest/` 下载别名自动跟随最新发行版。
- **升级路径**：Release 发布后，节点菜单 `[8] 检查更新升级` 依赖 `config.yaml` 的 `update.url`（`https://gitcode.com/Kealy/webshell-guard-go/releases/download/latest/manifest.json`）。
