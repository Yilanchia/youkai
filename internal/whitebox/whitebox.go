package whitebox

import (
	"context"
	"fmt"
	"strings"

	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// Capability registration. One capability, no network, no execution.

// Env is the per-engagement context.
type Env struct {
	Store        *ledger.Store
	EngagementID int64
	Engagement   string
}

// Capability is one typed, bounded analysis action.
type Capability struct {
	Name        string
	Description string
	Tier        gate.Tier
	Run         func(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error)
}

var registry = []Capability{
	{
		Name: "code_ingest",
		Description: "Read an application's source tree locally: discover routes, trace parameters toward dangerous sinks, " +
			"and record hypotheses for the black-box side to verify. No requests, no execution, no source text kept. | " +
			"中文:本地读源码,识别路由与 source→sink 线索,产出可验证假设;不发请求、不执行、不留源码正文。",
		Tier: gate.TierReadOnly,
		Run:  codeIngest,
	},
}

var capabilityIndex = func() map[string]Capability {
	m := map[string]Capability{}
	for _, c := range registry {
		m[c.Name] = c
	}
	return m
}()

// Lookup returns a capability by name.
func Lookup(name string) (Capability, bool) {
	c, ok := capabilityIndex[name]
	return c, ok
}

// Registry lists every capability this package offers, in presentation order.
func Registry() []Capability { return registry }

// Names lists the registered capabilities.
func Names() []string {
	out := make([]string, 0, len(registry))
	for _, c := range registry {
		out = append(out, c.Name)
	}
	return out
}

// codeIngest is the entry point: read the tree, keep the map, drop the source.
func codeIngest(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	if env == nil || env.Store == nil {
		return ledger.Observation{}, fmt.Errorf("whitebox: no environment")
	}
	root, _ := args["path"].(string)
	root = strings.TrimSpace(root)
	if root == "" {
		return ledger.Observation{}, fmt.Errorf("whitebox: 需要 path(源码目录)")
	}
	if err := ctx.Err(); err != nil {
		return ledger.Observation{}, err
	}
	rep, err := Ingest(root)
	if err != nil {
		return ledger.Observation{}, err
	}

	// The whitebox package does not import the ledger's row type; convert at the
	// boundary so the ledger stays the single owner of persisted shapes.
	rows := make([]ledger.Hypothesis, 0, len(rep.Hypotheses))
	for _, h := range rep.Hypotheses {
		rows = append(rows, ledger.Hypothesis{
			Kind: h.Kind, Entry: h.Entry, Param: h.Param, Sink: h.Sink,
			Path: h.Path, Confidence: h.Confidence, Note: h.Note, File: h.File, Line: h.Line,
		})
	}
	saved, err := env.Store.SaveHypotheses(ctx, env.EngagementID, rows)
	if err != nil {
		return ledger.Observation{}, err
	}

	obs := ledger.Observation{}
	// Assets: one per route, so the code view and the network view can be joined.
	routeCap := len(rep.Routes)
	if routeCap > 60 {
		routeCap = 60
	}
	for _, r := range rep.Routes[:routeCap] {
		obs.Assets = append(obs.Assets, ledger.AssetSeed{
			Kind:  "code-endpoint",
			Value: "code:" + r.Method + " " + r.Path,
			Props: map[string]any{
				"method": r.Method, "path": r.Path, "file": r.File, "line": r.Line,
				"auth": r.Auth, "framework": r.Framework,
			},
		})
	}

	obs.Facts = append(obs.Facts, ledger.FactSeed{
		Statement: fmt.Sprintf("源码分析:%s 下的 %d 个文件、%d 行;识别出 %d 条路由、%d 条线索(全部为代码线索,未经运行验证)",
			rep.Root, rep.Files, rep.Lines, len(rep.Routes), len(rep.Hypotheses)),
		Evidence: map[string]any{
			"root": rep.Root, "files": rep.Files, "lines": rep.Lines,
			"routes": len(rep.Routes), "hypotheses": len(rep.Hypotheses), "saved": saved,
		},
	})
	for _, h := range rep.Hypotheses {
		if len(obs.Facts) > 40 {
			break
		}
		obs.Facts = append(obs.Facts, ledger.FactSeed{
			Statement: fmt.Sprintf("线索(%s):%s 的参数 %s 可能%s — %s", h.Sink, h.Entry, h.Param, h.Note, h.Path),
			Evidence: map[string]any{
				"hypothesis": true, "sink": h.Sink, "entry": h.Entry, "param": h.Param,
				"path": h.Path, "confidence": "code-only",
			},
		})
	}
	if len(rep.Warnings) > 0 {
		obs.Facts = append(obs.Facts, ledger.FactSeed{
			Statement: "源码分析注意事项:" + strings.Join(rep.Warnings, ";"),
		})
	}
	return obs, nil
}
