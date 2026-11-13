package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// Capability is one account-layer capability.
type Capability struct {
	Name        string
	Description string
	Tier        gate.Tier
	Run         func(ctx context.Context, env Env, args map[string]any) (ledger.Observation, error)
}

var capabilities []Capability

func init() {
	capabilities = []Capability{
		{
			Name: "accounts_show",
			Description: "账号清单只读视图:name/role/owns.marker/session_ready + BOLA 配对;" +
				"不回 cookie/密码",
			Tier: gate.Classify("accounts_show", nil),
			Run:  runShow,
		},
		{
			Name:        "accounts_provision",
			Description: "按清单每个账号只登录一次,存命名会话;密码只从 password_env 取",
			Tier:        gate.Classify("accounts_provision", nil),
			Run:         runProvision,
		},
		{
			Name:        "accounts_seed",
			Description: "对象播种:每账号创建一个最小对象作为归属真值(需 allow_object_seeding + POST + confirm)",
			Tier:        gate.Classify("accounts_seed", nil),
			Run:         runSeed,
		},
		{
			Name:        "object_seed",
			Description: "accounts_seed 的同义能力(对象播种,档 2)",
			Tier:        gate.Classify("object_seed", nil),
			Run:         runSeed,
		},
		{
			Name:        "accounts_register",
			Description: "自助注册一次;撞到 CAPTCHA/手机/SMS/OTP 即停,邮箱验证只接受人工 verification_url",
			Tier:        gate.Classify("accounts_register", nil),
			Run:         runRegister,
		},
		{
			Name:        "reachability",
			Description: "high-auth 校验后的多身份只读可达性图(只复用 GET,不横向)",
			Tier:        gate.Classify("reachability", nil),
			Run:         runReach,
		},
	}
}

// Registry returns every account capability.
func Registry() []Capability {
	out := make([]Capability, len(capabilities))
	copy(out, capabilities)
	return out
}

// Lookup finds a capability by name.
func Lookup(name string) (Capability, bool) {
	want := strings.ToLower(strings.TrimSpace(name))
	for _, c := range capabilities {
		if strings.ToLower(c.Name) == want {
			return c, true
		}
	}
	return Capability{}, false
}

// Run dispatches one capability.
func Run(ctx context.Context, env Env, name string, args map[string]any) (ledger.Observation, error) {
	c, ok := Lookup(name)
	if !ok {
		return ledger.Observation{}, fmt.Errorf("accounts: unknown capability %q", name)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.Run(ctx, env, args)
}

// ---- implementations -------------------------------------------------------

func runShow(ctx context.Context, env Env, _ map[string]any) (ledger.Observation, error) {
	svc, err := Open(env)
	if err != nil {
		return ledger.Observation{}, err
	}
	view, err := svc.Show()
	if err != nil {
		return ledger.Observation{}, err
	}
	obs := ledger.Observation{Summary: fmt.Sprintf("accounts: %d identities, %d BOLA pairs",
		len(view.Accounts), len(view.BolaPairs))}
	for _, a := range view.Accounts {
		obs.Facts = append(obs.Facts, ledger.FactSeed{
			Statement: fmt.Sprintf("账号 %s (%s),session_ready=%v,owns=%v",
				a.Name, a.Role, a.SessionReady, a.Owns),
			Evidence: map[string]any{"manifest": view.Path, "role": a.Role},
			Tags:     []string{"account", a.Role},
			Anchors:  []string{"account:" + a.Name},
		})
		obs.Assets = append(obs.Assets, ledger.AssetSeed{
			Kind: "account", Value: "account:" + a.Name,
			Props: map[string]any{"role": a.Role, "session_ready": a.SessionReady, "owns": a.Owns},
		})
	}
	for _, p := range view.BolaPairs {
		obs.Summary += ";" + p.Note
	}
	return obs, nil
}

func runProvision(ctx context.Context, env Env, args map[string]any) (ledger.Observation, error) {
	svc, err := Open(env)
	if err != nil {
		return ledger.Observation{}, err
	}
	obs, rep, err := svc.Provision(ctx, argStrings(args, "only"))
	if err != nil {
		return ledger.Observation{}, err
	}
	for _, f := range rep.Failed {
		obs.Facts = append(obs.Facts, ledger.FactSeed{
			Statement: fmt.Sprintf("账号 %s 登录失败:%s", f.Name, f.Error),
			Evidence:  map[string]any{"manifest": svc.Manifest.Path, "error": f.Error},
			Tags:      []string{"account", "login-failed"},
			Anchors:   []string{"account:" + f.Name},
		})
	}
	if len(rep.Provisioned) == 0 && len(rep.Failed) > 0 {
		return obs, fmt.Errorf("accounts: 没有账号登录成功(%d 个失败)", len(rep.Failed))
	}
	return obs, nil
}

func runSeed(ctx context.Context, env Env, args map[string]any) (ledger.Observation, error) {
	svc, err := Open(env)
	if err != nil {
		return ledger.Observation{}, err
	}
	obs, _, err := svc.Seed(ctx, argBool(args, "confirm"), argStrings(args, "only"))
	return obs, err
}

func runRegister(ctx context.Context, env Env, args map[string]any) (ledger.Observation, error) {
	svc, err := Open(env)
	if err != nil {
		return ledger.Observation{}, err
	}
	obs, _, err := svc.Register(ctx, args)
	if errors.Is(err, ErrNeedsHuman) {
		// The observation still carries the fact; the error tells the caller a
		// human must continue. The API turns this into "needs_human", not a retry.
		return obs, err
	}
	return obs, err
}

func runReach(ctx context.Context, env Env, args map[string]any) (ledger.Observation, error) {
	svc, err := Open(env)
	if err != nil {
		return ledger.Observation{}, err
	}
	obs, _, err := svc.Reachability(ctx,
		argStrings(args, "urls"),
		argStrings(args, "sessions"),
		argString(args, "high_auth_path"),
		argBoolDefault(args, "include_anonymous", true),
	)
	return obs, err
}

// ---- arg helpers -----------------------------------------------------------

func argString(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	s, _ := args[key].(string)
	return s
}

func argStrings(args map[string]any, key string) []string {
	if args == nil {
		return nil
	}
	switch v := args[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	}
	return nil
}

func argBool(args map[string]any, key string) bool {
	if args == nil {
		return false
	}
	b, _ := args[key].(bool)
	return b
}

func argBoolDefault(args map[string]any, key string, def bool) bool {
	if args == nil {
		return def
	}
	if b, ok := args[key].(bool); ok {
		return b
	}
	return def
}
