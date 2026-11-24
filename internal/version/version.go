// Package version 程序版本信息。
// Version/BuildDate 默认为 dev，正式发布时由 build.bat 通过 -ldflags 注入：
//
//	go build -ldflags "-X webshell-guard/internal/version.Version=v1.0.1 -X webshell-guard/internal/version.BuildDate=20261124"
package version

import "fmt"

var (
	// Version 当前版本号（v1.2.3 或 dev）。
	Version = "dev"
	// BuildDate 构建时间（yyyyMMdd-HHmmss）。
	BuildDate = ""
)

// String 返回展示用版本串。
func String() string {
	if BuildDate == "" {
		return Version
	}
	return fmt.Sprintf("%s (build %s)", Version, BuildDate)
}
