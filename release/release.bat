@echo off
setlocal enabledelayedexpansion
REM ============================================================
REM  Release builder for webshell-guard-go
REM  Usage:  release.bat v1.0.1
REM  Output: release\dist\webshell-guard.exe + manifest.json
REM  Then publish 3 files to BOTH gitcode and GitHub Releases (tag = vX.Y.Z).
REM ============================================================

set VERSION=%1
if "%VERSION%"=="" (
    echo Usage: release.bat v1.0.1   [version must match git tag, e.g. v1.0.1]
    exit /b 1
)

set REPO=https://gitcode.com/Kealy/webshell-guard-go
REM 节点升级源为 gitcode(国内可达); gitcode 的 releases/download/latest/ 别名自动跟随最新发行版
set ASSET_TAG=latest
set GH_REPO=https://github.com/samdan0809/webshell-guard-go
set DIST=release\dist
set BUILDTIME=

for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set BUILDTIME=%%i
if "%BUILDTIME%"=="" set BUILDTIME=0

if not exist %DIST% mkdir %DIST%

echo [1/4] Building %VERSION% ...
go build -o %DIST%\webshell-guard.exe -ldflags "-X webshell-guard/internal/version.Version=%VERSION% -X webshell-guard/internal/version.BuildDate=%BUILDTIME%"
if errorlevel 1 (
    echo [FAIL] go build failed
    exit /b 1
)

echo [2/4] Computing SHA256 ...
for /f %%h in ('powershell -NoProfile -Command "(Get-FileHash '%DIST%\webshell-guard.exe' -Algorithm SHA256).Hash.ToLower()"') do set SHA=%%h
if "!SHA!"=="" (
    echo [FAIL] failed to compute sha256
    exit /b 1
)
echo     sha256 = !SHA!
echo !SHA!  webshell-guard.exe > %DIST%\webshell-guard.exe.sha256

echo [3/4] Writing manifest.json ...
(
echo {"version":"%VERSION%","url":"%REPO%/releases/download/%ASSET_TAG%/webshell-guard.exe","sha256":"!SHA!","notes":"Release %VERSION%"}
) > %DIST%\manifest.json

echo [4/4] Done. Files in %DIST%:
dir /b %DIST%

echo.
echo Next: publish 3 files to BOTH platforms, release tag = %VERSION%
echo   [gitcode] https://gitcode.com/Kealy/webshell-guard-go/releases
echo             新建发行版选标签 %VERSION%, 上传 webshell-guard.exe / manifest.json / webshell-guard.exe.sha256
echo             (下载别名 %REPO%/releases/download/latest/ 自动跟随最新发行版)
echo   [github ] https://github.com/samdan0809/webshell-guard-go/releases/new
echo             或 gh CLI : gh release create %VERSION% "%DIST%\webshell-guard.exe" "%DIST%\manifest.json" "%DIST%\webshell-guard.exe.sha256" --title "%VERSION%" --notes "Release %VERSION%"
echo.
echo Node config:  update.url = %REPO%/releases/download/%ASSET_TAG%/manifest.json
