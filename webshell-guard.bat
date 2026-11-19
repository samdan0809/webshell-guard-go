@echo off
title webshell-guard 管理器
setlocal

REM ============================================
REM  webshell-guard 管理脚本 (ANSI/GBK 编码)
REM  放在 webshell-guard.exe 同目录下运行
REM  注意：用记事本编辑后请"另存为-ANSI编码"，否则中文乱码
REM ============================================

cd /d "%~dp0"

REM ---- 自动提权到管理员（服务安装/卸载需要） ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在请求管理员权限...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

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
