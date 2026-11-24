// Package tray Windows 任务栏托盘图标：
// 左键/双击打开 Web 监控面板；右键菜单（打开面板/退出）；
// 有新告警时图标变红、悬停提示告警数；打开面板后恢复绿色。
package tray

import (
	"fmt"
	"os/exec"
	"sync/atomic"
	"time"

	"fyne.io/systray"
)

var (
	panelURL     string
	quitFn       func()
	updFn        func() string // 检查更新回调，返回提示文本
	alertCnt     atomic.Int32
	pendingAlert atomic.Bool
	started      atomic.Bool
	lastOpen     time.Time
)

// SetUpdateHandler 注入「检查更新」回调（控制台模式下由 main 设置）。
func SetUpdateHandler(fn func() string) { updFn = fn }

// Start 启动托盘图标（非阻塞）。panelURL 为监控面板地址，可为空。
// onQuit 为用户点「退出程序」时停止核心逻辑的回调，可为空。
func Start(url string, onQuit func()) {
	panelURL = url
	quitFn = onQuit
	go systray.Run(onReady, func() {})
}

func onReady() {
	started.Store(true)
	systray.SetIcon(greenIconData())
	systray.SetTooltip(plainTooltip())

	if panelURL != "" {
		mOpen := systray.AddMenuItem("打开监控面板", panelURL)
		go func() {
			for range mOpen.ClickedCh {
				openPanel()
			}
		}()
		// 左键/双击托盘图标 → 打开面板（右键默认弹菜单）
		systray.SetOnTapped(openPanel)
	}
	if updFn != nil {
		mUpd := systray.AddMenuItem("检查更新", "检查是否有新版本")
		go func() {
			for range mUpd.ClickedCh {
				// 检查涉及网络请求，放后台执行避免阻塞菜单线程
				go func() {
					if msg := updFn(); msg != "" {
						systray.SetTooltip("webshell-guard | " + msg)
					}
				}()
			}
		}()
	}
	mQuit := systray.AddMenuItem("退出程序", "停止 webshell-guard")
	go func() {
		for range mQuit.ClickedCh {
			systray.Quit()
			if quitFn != nil {
				quitFn()
			}
		}
	}()

	if pendingAlert.Load() {
		applyAlert()
	}
}

// NotifyAlert 有一条新告警：计数 +1，图标变红。
func NotifyAlert() {
	alertCnt.Add(1)
	pendingAlert.Store(true)
	if started.Load() {
		applyAlert()
	}
}

func applyAlert() {
	n := alertCnt.Load()
	systray.SetIcon(redIconData())
	systray.SetTooltip(fmt.Sprintf("webshell-guard ⚠ 有 %d 条告警待处理（双击打开面板）", n))
}

func openPanel() {
	if panelURL == "" {
		return
	}
	// 重置告警状态
	pendingAlert.Store(false)
	alertCnt.Store(0)
	systray.SetIcon(greenIconData())
	systray.SetTooltip(plainTooltip())

	// 双击会触发两次点击回调：600ms 内只开一次
	if time.Since(lastOpen) < 600*time.Millisecond {
		return
	}
	lastOpen = time.Now()
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", panelURL).Start()
}

func plainTooltip() string {
	if panelURL != "" {
		return fmt.Sprintf("webshell-guard 运行中 | 双击打开面板 %s", panelURL)
	}
	return "webshell-guard 运行中"
}
