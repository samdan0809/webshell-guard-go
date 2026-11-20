// webshell-guard：ASPX/ASHX 挂马与 webshell 实时监控处置工具。
// 支持 控制台运行 与 Windows 服务（守护进程）双模式。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"

	"webshell-guard/internal/action"
	"webshell-guard/internal/config"
	"webshell-guard/internal/detector"
	"webshell-guard/internal/monitor"
	"webshell-guard/internal/notify"
	"webshell-guard/internal/rules"
	"webshell-guard/internal/tray"
	"webshell-guard/internal/webui"
)

func main() {
	cfgPath := flag.String("c", "config.yaml", "配置文件路径")
	svcCmd := flag.String("s", "", "服务管理: install | uninstall | start | stop | watchdog")
	flag.Parse()

	// 服务管理命令
	if *svcCmd != "" {
		if err := serviceControl(*svcCmd, *cfgPath); err != nil {
			log.Fatalf("服务操作失败: %v", err)
		}
		return
	}

	// 由服务控制管理器(SCM)拉起 → 走守护模式
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		runService(*cfgPath)
		return
	}

	// 控制台模式
	stop := make(chan struct{})
	var closeOnce sync.Once
	closeStop := func() { closeOnce.Do(func() { close(stop) }) }
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("收到信号 %v, 准备退出", sig)
		closeStop()
	}()
	if err := runCore(*cfgPath, stop, closeStop, true); err != nil {
		log.Fatalf("运行失败: %v", err)
	}
}

// runCore 核心运行逻辑（控制台/服务共用）。stop 关闭时优雅退出。
// stopFn 供托盘「退出程序」菜单调用（服务模式传 nil）；withTray 控制台模式显示托盘图标。
func runCore(cfgPath string, stop <-chan struct{}, stopFn func(), withTray bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("CONFIG: %w", err) // 前缀标记：配置错误不应触发服务重启循环
	}
	setupLogger(cfg.LogFile)

	log.Printf("=== webshell-guard 启动 ===")
	log.Printf("监控目录: %v", cfg.WatchDirs)
	log.Printf("扩展名: %v | 处置模式: %s | 判恶阈值: %d", cfg.Extensions, cfg.Action, cfg.ScoreThreshold)

	det := detector.New(cfg.ScoreThreshold, cfg.DomainWhitelist, cfg.ExtraKeywords)

	// 内置规则外部化：rules_builtin.yaml 存在则加载覆盖代码默认（改规则无需重编译）；
	// 不存在则生成一份可编辑副本，方便运维直接改 score/pattern/enabled。
	workDir := filepath.Dir(cfgPath)
	builtinPath := filepath.Join(workDir, "rules_builtin.yaml")
	if defs, err := rules.LoadBuiltinRules(builtinPath); err != nil {
		log.Printf("[rules-builtin] 加载失败, 使用代码默认规则: %v", err)
	} else if defs != nil {
		if merged, merr := rules.ResolveBuiltinRules(defs, det.BuiltinRules()); merr != nil {
			log.Printf("[rules-builtin] 规则校验失败, 使用代码默认规则: %v", merr)
		} else {
			det.SetBuiltinRules(merged)
			log.Printf("[rules-builtin] 已从 %s 加载 %d 条内置规则", builtinPath, len(merged))
		}
	} else {
		if err := rules.SaveBuiltinRules(builtinPath, rules.BuiltinRulesToDefs(det.BuiltinRules())); err != nil {
			log.Printf("[rules-builtin] 生成可编辑副本失败: %v", err)
		} else {
			log.Printf("[rules-builtin] 已生成可编辑副本: %s", builtinPath)
		}
	}

	// 本地自定义规则库（rules_custom.yaml）
	ruleStore := rules.New(filepath.Join(workDir, "rules_custom.yaml"))

	// 共享规则同步器（Git/raw 定时拉取，缓存 rules_synced.yaml）
	syncer := rules.NewSyncer(rules.RepoConfig{
		Enabled:    cfg.RulesSync.Enabled,
		Mode:       cfg.RulesSync.Mode,
		Repo:       cfg.RulesSync.Repo,
		Branch:     cfg.RulesSync.Branch,
		Interval:   cfg.RulesSync.Interval,
		Token:      cfg.RulesSync.Token,
		AuthHeader: cfg.RulesSync.AuthHeader,
		Files:      cfg.RulesSync.Files,
	}, filepath.Dir(cfgPath))

	// 面板访问口令：未配置则生成随机口令并打印到日志（重启后变化；如需固定请在 config.yaml 配 ui.token）。
	if cfg.UI.Enabled && cfg.UI.Token == "" {
		cfg.UI.Token = genPanelToken()
		log.Printf("Web 面板未配置 ui.token, 已生成临时口令: %s (浏览器弹出的用户名任意, 密码填此值)", cfg.UI.Token)
	}

	// 合并注入：同 ID 时本地/共享规则覆盖内置规则，也可作为新增规则追加；本地优先于共享。
	applyRules := func() {
		localDefs := ruleStore.List()
		syncedDefs := syncer.SyncedDefs()
		allDefs := rules.MergeDefs(localDefs, syncedDefs)
		// 内置规则可被同 ID 的共享/本地规则热覆盖（改内置规则无需重编译/重启）
		base := det.BuiltinBaseRules()
		det.SetBuiltinOverrides(base, rules.OverrideBuiltinByDefs(base, allDefs))
		merged := rules.MergeRules(ruleStore.DetectorRules(), syncer.DetectorRules())
		det.SetCustomRules(merged)
		log.Printf("自定义规则已加载: 本地 %d 条 + 共享 %d 条", ruleStore.Count(), len(syncedDefs))
	}
	syncer.OnUpdate = applyRules
	syncer.LoadCache() // 断源兜底：先用上次缓存
	applyRules()

	// 同步循环常驻：未启用时 SyncNow 自动跳过；面板可随时热启用
	go func() {
		if err := syncer.SyncNow(); err != nil {
			log.Printf("[rules-sync] 首次同步失败(使用本地缓存继续防护): %v", err)
		}
		syncer.Start(stop)
	}()
	var baseline *detector.Baseline
	if cfg.Baseline.Enabled {
		baseline = detector.NewBaseline(cfg.Baseline.File)
		log.Printf("基线已加载: %s (%d 条)", cfg.Baseline.File, baseline.Count())
	} else {
		baseline = detector.NewBaseline("") // 空基线，不落盘
	}

	notifier := notify.New(cfg.Webhook, cfg.AlertCooldown)
	exec := action.New(cfg, notifier, baseline)

	// 任务栏托盘图标（仅控制台模式；服务模式在会话0里无交互界面）
	if withTray {
		panelURL := ""
		if cfg.UI.Enabled {
			panelURL = fmt.Sprintf("http://localhost:%d", cfg.UI.Port)
		}
		tray.Start(panelURL, stopFn)
		log.Printf("托盘图标已启动(双击打开面板, 右键菜单)")
	}

	engine, err := monitor.New(cfg, det, exec, baseline)
	if err != nil {
		return fmt.Errorf("初始化监控失败: %w", err)
	}
	defer engine.Close()

	// 处置回调链：Web UI 实时推送 + 托盘告警标记
	var uiHandler func(action.History)
	if cfg.UI.Enabled {
		ui := webui.New(cfg, det, engine, notifier, ruleStore, syncer, cfgPath)
		uiHandler = ui.Handler()
		go func() {
			log.Printf("Web 面板已启动: http://localhost:%d", cfg.UI.Port)
			if err := ui.Start(); err != nil {
				log.Printf("Web 面板启动失败: %v", err)
			}
		}()
	}
	exec.OnHandled = func(h action.History) {
		if uiHandler != nil {
			uiHandler(h)
		}
		if withTray {
			tray.NotifyAlert()
		}
	}

	watchCh := make(chan string, 16)
	errCh := make(chan error, 1)

	go func() {
		engine.Run(watchCh, errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-stop:
		return nil
	}
}

// genPanelToken 生成 16 字节随机面板口令。
func genPanelToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// setupLogger 同时输出到控制台和文件。
func setupLogger(logFile string) {
	if dir := filepath.Dir(logFile); dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(io.MultiWriter(os.Stdout, f))
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
