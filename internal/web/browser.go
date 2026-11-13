package web

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"youkai/internal/ledger"
)

// Browser rendering is registered but deliberately degraded in this build.
//
// A CDP backend drives a real browser to a URL. That navigation is an egress the
// guard cannot see: the browser process opens its own sockets, resolves its own
// hosts, and follows its own redirects. Rather than adding a second, unaudited
// egress path, this capability does the capability-detection half honestly and
// then refuses:
//
//   - no Chrome/Edge on the machine  -> ErrUnavailable ("not installed");
//   - a browser is present           -> ErrUnavailable ("no audited CDP bridge").
//
// Both are refusals with precise reasons, and no request is ever sent unguarded.

func runBrowser(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	if _, err := guardOf(env); err != nil {
		// Discipline first: without a passport nothing runs, browser or not.
		return ledger.Observation{}, err
	}

	path := detectBrowser()
	if path == "" {
		return ledger.Observation{}, fmt.Errorf(
			"%w: 本机未找到 Chrome/Edge(已检查 PATH 与常见安装目录);browser 需要 CDP 渲染后端,"+
				"本构建不发送任何未受 guard 审计的请求", ErrUnavailable)
	}
	return ledger.Observation{}, fmt.Errorf(
		"%w: 已检测到浏览器(%s),但本构建不实现 CDP 渲染:页面导航无法经 discipline.Guard 审计,"+
			"因此拒绝打开第二条对外通道", ErrUnavailable, filepath.Base(path))
}

// detectBrowser looks for a Chromium-family executable without launching it.
func detectBrowser() string {
	names := []string{
		"chrome", "chrome.exe",
		"google-chrome", "google-chrome-stable",
		"chromium", "chromium-browser",
		"msedge", "msedge.exe", "microsoft-edge",
	}
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil && p != "" {
			return p
		}
	}
	roots := []string{
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("LocalAppData"),
	}
	relatives := []string{
		filepath.Join("Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join("Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join("Chromium", "Application", "chrome.exe"),
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		for _, rel := range relatives {
			candidate := filepath.Join(root, rel)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
	}
	return ""
}
