@echo off
REM 构建脚本：可带版本号参数，如 build.bat v1.0.1；不带参数默认 dev
setlocal
set VERSION=%1
if "%VERSION%"=="" set VERSION=dev
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set BUILDTIME=%%i
go build -o webshell-guard.exe -ldflags "-X webshell-guard/internal/version.Version=%VERSION% -X webshell-guard/internal/version.BuildDate=%BUILDTIME%"
if %errorlevel% neq 0 (
    echo 构建失败
    exit /b 1
)
echo 构建成功: webshell-guard.exe (版本 %VERSION%, %BUILDTIME%)
