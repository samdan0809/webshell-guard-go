//go:build windows

// Windows 服务守护模式：
//  1. SYSTEM 权限运行，普通进程无权 kill
//  2. SCM 恢复策略：进程被强杀 → 5s/30s/60s 自动重启
//  3. 计划任务看门狗：每分钟检查，被 stop 也能拉活
//  4. 收到停止请求时先发 webhook 告警（留证据）
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"webshell-guard/internal/config"
	"webshell-guard/internal/notify"
)

const svcName = "webshell-guard"

// runService 以服务模式运行（由 SCM 拉起时调用）。
func runService(cfgPath string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[service] PANIC: %v", r)
		}
	}()
	// 服务模式 stdout 不可见，先把服务级日志落文件（exe 同目录 service.log）
	if exe, err := os.Executable(); err == nil {
		if f, ferr := os.OpenFile(filepath.Join(filepath.Dir(exe), "service.log"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); ferr == nil {
			log.SetOutput(io.MultiWriter(f))
			log.SetFlags(log.LstdFlags | log.Lshortfile)
			log.Printf("=== 服务进程启动 (pid=%d) ===", os.Getpid())
		}
	}
	if err := svc.Run(svcName, &guardService{cfgPath: cfgPath}); err != nil {
		log.Printf("[service] svc.Run 返回错误: %v", err)
	}
	log.Printf("[service] svc.Run 已返回, 服务进程退出")
}

type guardService struct{ cfgPath string }

// Execute 实现 svc.Handler。
func (g *guardService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: 15000}

	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- runCore(g.cfgPath, stop, nil, false) }()

	status <- svc.Status{State: svc.Running, Accepts: 0} // 不接受 STOP 控制码 → 任何 sc stop/Stop-Service 都会被 SCM 拒绝
	log.Printf("[service] 守护服务已进入运行状态(已拒绝外部停止控制)")

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			}
		case err := <-done:
			// 核心自行退出：配置错误 → 正常报告 Stopped 不重启；其他异常 → 故障码终止触发重启
			if err != nil && strings.HasPrefix(err.Error(), "CONFIG:") {
				status <- svc.Status{State: svc.Stopped}
				log.Printf("[service] 配置错误, 不自动重启: %v", err)
				return false, 0
			}
			log.Printf("[service] 核心异常退出, 即以故障码终止触发SCM重启: %v", err)
			os.Exit(2)
		}
	}
}

// alertStopRequest 停止请求告警。
func alertStopRequest(cfgPath string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return
	}
	host, _ := os.Hostname()
	n := notify.New(cfg.Webhook, cfg.AlertCooldown)
	n.Send(notify.Alert{
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Host:   host,
		File:   "(!守护服务收到停止请求!)",
		Action: "service_stop_request",
	}, 0)
	log.Printf("[service] 已推送停止请求告警")
}

// serviceControl 服务管理入口（-s 参数）。
func serviceControl(cmd, cfgPath string) error {
	switch cmd {
	case "install":
		return svcInstall(cfgPath)
	case "uninstall":
		return svcUninstall()
	case "start":
		return svcStart()
	case "stop":
		return svcStop()
	case "watchdog":
		return svcWatchdog()
	default:
		return fmt.Errorf("未知命令 %s (支持 install|uninstall|start|stop|watchdog)", cmd)
	}
}

func svcConnect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("连接服务管理器失败(需要管理员权限): %v", err)
	}
	return m, nil
}

// svcInstall 安装守护服务 + SCM 恢复策略 + 看门狗计划任务。
func svcInstall(cfgPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	cfgAbs, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}

	m, err := svcConnect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return fmt.Errorf("服务已存在, 如需重装请先执行: %s -s uninstall", exe)
	}

	s, err := m.CreateService(svcName, exe, mgr.Config{
		DisplayName: "Webshell Guard",
		Description: "网站脚本(aspx/php/jsp)挂马与 webshell 实时监控处置守护服务",
		StartType:   mgr.StartAutomatic, // 开机自启
	}, "-c", cfgAbs)
	if err != nil {
		return fmt.Errorf("创建服务失败: %v", err)
	}
	defer s.Close()

	// SCM 恢复策略：失败后 5s → 30s → 60s 循环重启（防强杀）
	recovery := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	if err := s.SetRecoveryActions(recovery, 86400); err != nil {
		log.Printf("[service] 设置恢复策略失败(服务已装, 建议手动 sc failure %s reset= 86400 actions= restart/5000): %v", svcName, err)
	}

	// 计划任务看门狗：SYSTEM 权限每分钟检查，服务不在运行态就拉起
	watchdogCmd := exec.Command("schtasks", "/Create", "/F",
		"/SC", "MINUTE", "/MO", "1",
		"/TN", svcName+"-watchdog",
		"/TR", fmt.Sprintf(`"%s" -s watchdog`, exe),
		"/RU", "SYSTEM", "/RL", "HIGHEST")
	if out, err := watchdogCmd.CombinedOutput(); err != nil {
		log.Printf("[service] 创建看门狗计划任务失败(不影响服务本体): %v, %s", err, out)
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("服务已安装但启动失败: %v", err)
	}
	log.Printf("[service] 守护服务安装并启动成功")
	log.Printf("  服务名: %s | 开机自启 | 崩溃自动重启(5s/30s/60s)", svcName)
	log.Printf("  看门狗计划任务: %s-watchdog (每分钟检查)", svcName)
	log.Printf("  配置文件: %s", cfgAbs)
	return nil
}

// svcUninstall 卸载服务与看门狗。
func svcUninstall() error {
	m, err := svcConnect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		// 服务不存在：只清理可能残留的看门狗任务
		_ = exec.Command("schtasks", "/Delete", "/F", "/TN", svcName+"-watchdog").Run()
		return fmt.Errorf("服务不存在(已尝试清理看门狗任务)")
	}
	defer s.Close()

	// 关键顺序：先摘除所有自动拉起机制，再杀进程，最后删除。
	// 否则 kill 后 SCM 恢复策略(5s)/看门狗会把服务重新拉起，删除标记失效。
	// 1) 清除恢复策略(防 kill 触发 SCM 重启)
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.NoAction}}, 0)
	// 2) 禁用服务(防看门狗拉起)：读回现有配置避免零值覆盖其他字段
	if cur, cerr := s.Config(); cerr == nil {
		cur.StartType = mgr.StartDisabled
		_ = s.UpdateConfig(cur)
	}
	// 3) 删看门狗计划任务
	if out, err := exec.Command("schtasks", "/Delete", "/F", "/TN", svcName+"-watchdog").CombinedOutput(); err != nil {
		log.Printf("[service] 卸载: 删除看门狗任务失败(手动删除可忽略): %v, %s", err, out)
	}

	// 4) 强杀服务进程(服务拒绝 STOP 控制)
	st, qerr := s.Query()
	if qerr == nil && st.State != svc.Stopped && st.ProcessId != 0 {
		log.Printf("[service] 卸载: 强杀服务进程 PID=%d", st.ProcessId)
		h, herr := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, st.ProcessId)
		if herr == nil {
			_ = windows.TerminateProcess(h, 1)
			_, _ = windows.WaitForSingleObject(h, 10000)
			_ = windows.CloseHandle(h)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// 5) 删除服务（SCM 释放句柄可能滞后，重试几次）
	var delErr error
	for i := 0; i < 5; i++ {
		delErr = s.Delete()
		if delErr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if delErr != nil {
		return fmt.Errorf("删除服务失败(已禁用+已清恢复策略, 重启后彻底移除): %v", delErr)
	}
	log.Printf("[service] 守护服务已卸载")
	return nil
}

func svcStart() error {
	m, err := svcConnect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("服务不存在, 请先 install")
	}
	defer s.Close()
	return s.Start()
}

func svcStop() error {
	m, err := svcConnect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("服务不存在")
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	return err
}

// svcWatchdog 看门狗：服务不在运行态就拉起（由计划任务每分钟调用）。
func svcWatchdog() error {
	m, err := svcConnect()
	if err != nil {
		return err // 无权限时静默失败，计划任务不报错
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return nil // 服务未安装则跳过
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return nil
	}
	if st.State != svc.Running && st.State != svc.StartPending && st.State != svc.StopPending {
		log.Printf("[watchdog] 检测到服务状态=%v, 自动拉起", st.State)
		return s.Start()
	}
	return nil
}
