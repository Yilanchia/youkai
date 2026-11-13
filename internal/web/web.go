// Package web is youkai's discipline-bound web capability layer.
//
// It is a native Go port of the evidence-gathering semantics Fairy proved out:
// the checks are the same (security headers, CORS, cookie flags, redirect chains,
// exposure probes, technology fingerprinting, dual-account comparison, parameter
// existence probes, WAF shape observation), but the implementation is idiomatic
// Go rather than a transliteration of the JavaScript.
//
// What matters here is the discipline, not the feature list:
//
//   - Every target request goes through Env.Guard.Do. This package contains no
//     HTTP client, no dialer, and no path to a target other than the guard. If a
//     capability cannot express itself as a guarded request (the CDP browser
//     backend), it returns ErrUnavailable instead of opening a second egress.
//   - Response bodies never leave memory. Facts carry a statement plus the
//     request_id of the audit row that proves them; findings carry a title, a
//     place, and a redacted detail. No Observation field ever holds a body.
//   - A check that cannot run says so. Capabilities return the error or emit a
//     fact stating the check did not run; they never emit a finding they cannot
//     back with a real request_id. The shared builder drops facts/findings that
//     would lack one, so this is structural rather than aspirational.
//   - Every loop is bounded: paths, pages, probes, variants, and requests have
//     small defaults and hard caps the caller cannot raise.
//
// Tiers come from internal/gate. Tier-2 capabilities are registered here but are
// proof-grade: the engine decides, at dispatch time, that a human approved the
// exact action. This package does not make that decision and cannot be argued
// into it by argument values; it only refuses to run when the scope itself has
// not unlocked the capability (allow_active_probes / allow_waf_probe / a
// write method for login).
package web

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"youkai/internal/discipline"
	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// ErrUnavailable means the capability exists in the registry but this build
// deliberately does not execute it. It is a refusal, never a silent success.
var ErrUnavailable = errors.New("web: capability unavailable in this build")

// Env is everything a capability may use. Store is provided for callers that
// already have it; capabilities return an Observation and never write rows
// themselves, so the ledger stays the only author of ids and lineage.
type Env struct {
	Guard        *discipline.Guard
	Store        *ledger.Store
	EngagementID int64
	Engagement   string
	// ArtifactDir holds non-secret artefacts: browser profiles and screenshots.
	// It is never used for response bodies.
	ArtifactDir string
}

// Capability is one registered web capability.
//
// Run returns an Observation or an error. It must not write to the ledger, must
// not invent request ids, and must not return a finding it cannot back with an
// audited request.
type Capability struct {
	Name        string
	Description string
	Tier        gate.Tier
	Run         func(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error)
}

var (
	registryOnce sync.Once
	capabilities []Capability
	capIndex     map[string]Capability
)

// Registry returns every web capability, in a stable order (tier 1 first).
func Registry() []Capability {
	initRegistry()
	out := make([]Capability, len(capabilities))
	copy(out, capabilities)
	return out
}

// Lookup finds a capability by name. Names are case-insensitive and trimmed.
func Lookup(name string) (Capability, bool) {
	initRegistry()
	c, ok := capIndex[strings.ToLower(strings.TrimSpace(name))]
	return c, ok
}

// Run dispatches one capability.
//
// Tier-2 capabilities are reachable through here on purpose: the engine calls
// Run only after internal/gate has classified the action and a human approved
// it. Run refuses unknown names rather than guessing.
func Run(ctx context.Context, env *Env, name string, args map[string]any) (ledger.Observation, error) {
	c, ok := Lookup(name)
	if !ok {
		return ledger.Observation{}, fmt.Errorf("web: unknown capability %q", strings.TrimSpace(name))
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.Run(ctx, env, args)
}

func initRegistry() {
	registryOnce.Do(func() {
		capabilities = []Capability{
			// ---- tier 1: read-only evidence ---------------------------------
			newCapability("probe", "单请求探测:经 guard 发一次请求,记录状态与 request_id", runProbe),
			newCapability("fingerprint", "技术指纹:只根据响应头/正文的正则命中推断技术栈", runFingerprint),
			newCapability("scan", "主检测:安全头、CORS、Cookie、跳转链、暴露面、版本泄露", runScan),
			newCapability("crawl", "同源 BFS 爬取:发现端点并登记资产,有页数与深度上限", runCrawl),
			newCapability("compare", "双账号比对:同一 URL 两组头部,判断标记是否两侧可见", runCompare),
			newCapability("role_matrix", "权限矩阵:多账号 × 多端点只读 GET,比较状态与长度", runRoleMatrix),
			newCapability("proof", "反射上下文判定:标记落在脚本/属性/注释/文本,并检测 CSP", runProof),
			newCapability("browser", "CDP 渲染:本构建无浏览器后端,返回 ErrUnavailable", runBrowser),
			newCapability("headers", "单项检查:安全响应头与版本泄露", runHeaders),
			newCapability("cors", "单项检查:CORS 任意源反射", runCORS),
			newCapability("exposures", "单项检查:敏感路径暴露面", runExposures),
			newCapability("redirect_check", "单项检查:跳转链与明文 HTTP 传输", runRedirectCheck),

			// ---- tier 2: proof-grade, human approval required ----------------
			newCapability("param", "参数存在性探测:仅 SQL 错误签名/布尔差分/SSTI 求值", runParam),
			newCapability("param_adaptive", "参数存在性探测 + 编码变体(不做绕过)", runParamAdaptive),
			newCapability("waf", "WAF 行为画像:只测规范化差异与拦截页,不生成绕过载荷", runWAF),
			newCapability("login", "单次登录尝试:经 guard 发一次写请求,只回 Cookie 名", runLogin),
		}
		capIndex = make(map[string]Capability, len(capabilities))
		for _, c := range capabilities {
			capIndex[strings.ToLower(c.Name)] = c
		}
	})
}

// newCapability fills in the tier from gate's table, so the registry can never
// disagree with the capability wall about what is proof-grade.
func newCapability(name, description string, run func(context.Context, *Env, map[string]any) (ledger.Observation, error)) Capability {
	return Capability{
		Name:        name,
		Description: description,
		Tier:        gate.Classify(name, nil),
		Run:         run,
	}
}
