@echo off
title webshell-guard 管理器
setlocal EnableExtensions

REM ============================================
REM  webshell-guard 管理脚本 (ANSI/GBK 编码)
REM  放在 webshell-guard.exe 同目录下运行
REM  注意：用记事本编辑后请"另存为-ANSI编码"，否则中文乱码
REM ============================================

cd /d "%~dp0"

REM ============================================
REM  管理员检测与自动提权 (防死循环版)
REM  1) 用 fltmc 检测权限: 不依赖 Server 服务,
REM     net session 在 LanmanServer 被禁用时会误判导致反复弹窗
REM  2) 提权时附带 elevated 参数, 若提权后仍检测失败,
REM     直接报错退出, 不再二次弹窗
REM ============================================
fltmc >nul 2>&1
if %errorlevel% equ 0 goto adminOk

if /i "%~1"=="elevated" goto elevateFailed

echo 正在请求管理员权限...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'elevated' -Verb RunAs"
if %errorlevel% neq 0 (
    echo.
    echo [!] 请求管理员权限失败: 可能取消了弹窗, 或系统 UAC 已被禁用。
    echo     请右键"以管理员身份运行"本脚本, 或在管理员 cmd 中运行。
    echo.
    pause
)
exit /b

:elevateFailed
echo.
echo [!] 已提权但管理员检测仍未通过, 常见原因:
echo     1) Server(LanmanServer) 服务被禁用, 可执行:
echo        sc config LanmanServer start= auto 然后 net start LanmanServer
echo     2) 当前账户不在管理员组。
echo     3) 组策略限制了提权。
echo     也可右键"以管理员身份运行"本脚本。
echo.
pause
exit /b

:adminOk
:menu
cls
echo ================================================
echo           webshell-guard 管理菜单
echo ================================================
echo   [1] 安装守护服务   (开机自启+防杀自愈, 服务器推荐)
echo   [2] 卸载守护服务
echo   [3] 启动守护服务
echo   [4] 停止守护服务
echo   [5] 控制台模式启动 (带任务栏托盘图标, 测试用)
echo   [6] 查看服务状态
echo   [7] 打开监控面板   (http://localhost:9090)
echo   [8] 检查更新升级   (从 GitHub 下载新版并自动重启)
echo   [0] 退出
echo.
echo   说明: 守护服务以 SYSTEM 权限后台运行, 无托盘图标;
echo         想用托盘请选 [5] 控制台模式。
echo ================================================
echo.
set /p choice=请输入编号后回车:
if "%choice%"=="1" goto install
if "%choice%"=="2" goto uninstall
if "%choice%"=="3" goto startsvc
if "%choice%"=="4" goto stopsvc
if "%choice%"=="5" goto console
if "%choice%"=="6" goto status
if "%choice%"=="7" goto panel
if "%choice%"=="8" goto update
if "%choice%"=="0" exit /b
goto menu

:install
call :checkConfig || goto menu
echo.
echo [安装] webshell-guard 守护服务...
"%~dp0webshell-guard.exe" -s install -c "%~dp0config.yaml"
echo.
pause
goto menu

:uninstall
echo.
echo [卸载] webshell-guard 守护服务与看门狗...
"%~dp0webshell-guard.exe" -s uninstall -c "%~dp0config.yaml"
echo.
pause
goto menu

:startsvc
echo.
echo [启动] 守护服务...
net start webshell-guard
if %errorlevel% neq 0 echo 启动失败, 请确认已执行过 [1] 安装。
echo.
pause
goto menu

:stopsvc
echo.
echo [停止] 注意: 服务已配置为拒绝外部停止控制(防恶意停止),
echo        如确需停止请直接选 [2] 卸载。
net stop webshell-guard
echo.
pause
goto menu

:console
call :checkConfig || goto menu
echo.
echo [启动] 控制台模式(含托盘图标), 窗口可最小化, 关闭窗口即退出...
start "webshell-guard" "%~dp0webshell-guard.exe" -c "%~dp0config.yaml"
timeout /t 2 >nul
echo 已在新窗口启动。日志: %~dp0webshell-guard.log
echo.
pause
goto menu

:status
echo.
sc query webshell-guard
echo.
pause
goto menu

:panel
start http://localhost:9090
goto menu

:update
call :checkConfig || goto menu
echo.
echo [升级] 检查更新, 如有新版本将下载替换并自动重启服务...
echo 提示: 需在 config.yaml 配置 update.url 指向 GitCode manifest 地址
"%~dp0webshell-guard.exe" -update -c "%~dp0config.yaml"
echo.
pause
goto menu

REM ---- 子过程: 确保 config.yaml 存在 ----
:checkConfig
if exist "%~dp0config.yaml" exit /b 0
if exist "%~dp0config.example.yaml" (
    copy /y "%~dp0config.example.yaml" "%~dp0config.yaml" >nul
    echo [!] 未找到 config.yaml, 已从 config.example.yaml 生成一份。
    echo     请先用记事本编辑 config.yaml: 改监控目录 watch_dirs 和 webhook 地址,
    echo     保存后再执行本操作。
    echo.
    pause
    exit /b 1
)
echo [!] 缺少 config.yaml 和 config.example.yaml, 请检查目录。
echo.
pause
exit /b 1
