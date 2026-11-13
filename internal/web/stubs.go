package web

import (
	"context"
	"fmt"

	"youkai/internal/ledger"
)

// Registered-but-not-implemented capabilities.
//
// These are not placeholders that pretend to work: each returns a precise reason
// and sends nothing. They are registered so the registry matches internal/gate's
// table exactly and the UI can show "needs the account layer" instead of "unknown
// capability".

func runReachability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	// The high-authorisation verifier lives in internal/discipline; the graph
	// itself needs the account layer to know who can reach what.
	return ledger.Observation{}, fmt.Errorf(
		"web: reachability 需要 high-auth 授权(FAIRY_AUTH_KEY 签名的 read-only grant 覆盖目标资产)才能生成多账号可达性图;" +
			"本构建的 internal/web 不实现该能力,未发送任何请求")
}

func runAccountsSeed(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	return ledger.Observation{}, fmt.Errorf(
		"web: accounts_seed 未在本构建实现:账号层(.fairy/accounts.json、加密会话存储、归属账本)不在 internal/web 范围内;" +
			"未发送任何请求,也未创建任何对象")
}

func runAccountsRegister(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	return ledger.Observation{}, fmt.Errorf(
		"web: accounts_register 未在本构建实现:需要账号层与人工处理 CAPTCHA/手机号/邮箱验证;" +
			"本构建不自动注册,未发送任何请求")
}

func runObjectSeed(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	return ledger.Observation{}, fmt.Errorf(
		"web: object_seed 未在本构建实现:对象播种需要账号层与对象归属标记(BOLA 配对);" +
			"未发送任何请求,也未创建任何对象")
}
