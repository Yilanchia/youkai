package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"youkai/internal/discipline"
	"youkai/internal/engine"
	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// handleIntents routes /api/engagements/{id}/intents[/{iid}[/{action}]]
func (s *Server) handleIntents(w http.ResponseWriter, r *http.Request, eng ledger.Engagement, tail []string) {
	if len(tail) == 0 {
		switch r.Method {
		case http.MethodGet:
			// Enrich with the tier the gate would assign right now, so the UI
			// never shows a stale classification.
			intents, err := s.cfg.Store.ListIntents(r.Context(), eng.ID)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "%v", err)
				return
			}
			out := make([]map[string]any, 0, len(intents))
			for _, it := range intents {
				dec := gate.Explain(it.Capability, it.Args)
				tier := it.Tier
				if int(dec.Tier) > tier {
					tier = int(dec.Tier)
				}
				out = append(out, map[string]any{
					"intent": it,
					"gate":   map[string]any{"tier": tier, "reason": dec.Reason, "autonomous": tier == 1},
				})
			}
			writeJSON(w, http.StatusOK, out)
		case http.MethodPost:
			s.createIntent(w, r, eng)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "GET or POST")
		}
		return
	}
	iid, err := parseID(tail[0])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad intent id")
		return
	}
	action := ""
	if len(tail) > 1 {
		action = tail[1]
	}
	switch action {
	case "":
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		it, err := s.cfg.Store.Intent(r.Context(), eng.ID, iid)
		if err != nil {
			writeErr(w, http.StatusNotFound, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, it)
	case "reject":
		s.rejectIntent(w, r, eng, iid)
	case "retry":
		s.retryIntent(w, r, eng, iid)
	case "approve":
		s.approveIntent(w, r, eng, iid)
	case "execute":
		s.executeIntent(w, r, eng, iid)
	case "approvals":
		list, err := s.cfg.Store.ListApprovals(r.Context(), eng.ID, iid)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, list)
	default:
		writeErr(w, http.StatusNotFound, "unknown intent action %q", action)
	}
}

// createIntent lets an operator queue one precise step by hand.
func (s *Server) createIntent(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	var body struct {
		Capability string         `json:"capability"`
		Args       map[string]any `json:"args"`
		Rationale  string         `json:"rationale"`
		Expected   string         `json:"expected_fact"`
		// Deps lets a conversational plan express order (v0.19): this step is not
		// claimable until those intents are done. Approval stays per-step, so a
		// dependency never grants authority - it only withholds it.
		Deps []int64 `json:"deps"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if strings.TrimSpace(body.Capability) == "" {
		writeErr(w, http.StatusBadRequest, "capability is required")
		return
	}
	if len([]rune(body.Rationale)) < 4 {
		writeErr(w, http.StatusBadRequest, "rationale is required (why this step?)")
		return
	}
	for _, dep := range body.Deps {
		if _, derr := s.cfg.Store.Intent(r.Context(), eng.ID, dep); derr != nil {
			writeErr(w, http.StatusBadRequest, "依赖的步骤 #%d 不属于这个作业", dep)
			return
		}
	}
	dec := gate.Explain(body.Capability, body.Args)
	spec := ledger.IntentSpec{
		Capability:       body.Capability,
		Args:             body.Args,
		Tier:             int(dec.Tier),
		Rationale:        body.Rationale,
		ExpectedFact:     body.Expected,
		GateReason:       dec.Reason,
		RequiresApproval: dec.Tier.NeedsHuman(),
		Deps:             body.Deps,
	}
	it, created, err := s.cfg.Store.EnsureIntent(r.Context(), eng.ID, spec)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	code := http.StatusCreated
	if !created {
		code = http.StatusOK
	}
	writeJSON(w, code, map[string]any{"intent": it, "created": created, "gate": dec})
}

// approveIntent records an operator approval. It does NOT execute anything.
func (s *Server) approveIntent(w http.ResponseWriter, r *http.Request, eng ledger.Engagement, iid int64) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var body struct {
		Operator     string `json:"operator"`
		Basis        string `json:"basis"`
		HighAuthPath string `json:"high_auth_path"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	it, err := s.cfg.Store.Intent(r.Context(), eng.ID, iid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "%v", err)
		return
	}
	// ADR-006: the approval is the human act. `high_auth_path` is accepted when a
	// deployment wants the extra check, but it is no longer what makes an approval
	// real - the authenticated token in the operator's browser is.
	// A basis is what makes the audit line readable later. An empty one - or a
	// stub like "ok" - is replaced with a real statement rather than rejected:
	// the operator already clicked, and a failed call here teaches nothing.
	if len([]rune(strings.TrimSpace(body.Basis))) < 8 {
		body.Basis = "operator approved in the UI @ " + time.Now().Format("2006-01-02 15:04:05")
	}
	nonce := ""
	if strings.TrimSpace(body.Operator) == "" {
		body.Operator = "operator"
	}
	if body.HighAuthPath != "" {
		if s.cfg.HighAuthKey == "" {
			writeErr(w, http.StatusPreconditionRequired,
				"high-auth file given but %s is not set on the server; cannot verify it", discipline.HighAuthKeyEnv)
			return
		}
		rec, err := discipline.LoadHighAuth(body.HighAuthPath)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		grant, err := rec.Verify(s.cfg.HighAuthKey, time.Now())
		if err != nil {
			writeErr(w, http.StatusForbidden, "%v", err)
			return
		}
		if target := targetOf(it.Capability, it.Args); target != "" && !grant.Covers(target) {
			writeErr(w, http.StatusForbidden, "high-auth record does not cover target %q", target)
			return
		}
		nonce = grant.Nonce
	}
	ap, err := s.cfg.Store.ApproveIntent(r.Context(), eng.ID, iid, body.Operator, body.Basis, body.HighAuthPath, nonce)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	s.hub.publish("approvals", map[string]any{"type": "approval", "intent_id": iid, "engagement": eng.Name})
	writeJSON(w, http.StatusCreated, ap)
}

// executeIntent is the only tier-2 execution route.
//
// One human condition is always required, and the approval is consumed atomically
// before anything runs:
//
//  1. an unconsumed operator approval whose fingerprint matches this intent;
//  2. only when the deployment sets RequireHighAuth, a valid high-auth record
//     covering that target (ADR-006: optional, off by default);
//  3. the passport must allow what the capability does.
//
// Exactly one capability executes, once. There is no batch form of this endpoint.
func (s *Server) executeIntent(w http.ResponseWriter, r *http.Request, eng ledger.Engagement, iid int64) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var body struct {
		Operator     string `json:"operator"`
		HighAuthPath string `json:"high_auth_path"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	ctx := r.Context()
	it, err := s.cfg.Store.Intent(ctx, eng.ID, iid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "%v", err)
		return
	}

	dec := gate.Explain(it.Capability, it.Args)
	tier := gate.Tier(it.Tier)
	if dec.Tier > tier {
		tier = dec.Tier
	}
	if tier.AutonomousOK() {
		writeErr(w, http.StatusBadRequest,
			"intent #%d is tier 1: it runs unattended in a run, not through the approval workbench", iid)
		return
	}

	// Both conditions are validated BEFORE the approval is consumed: a failed
	// precondition must not burn the single authorisation a human granted.
	//
	// Condition 1: a single-use operator approval bound to this exact action.
	pending, err := s.cfg.Store.PeekApproval(ctx, eng.ID, iid)
	if err != nil {
		writeErr(w, http.StatusForbidden, "%v", err)
		return
	}
	if strings.TrimSpace(body.Operator) != "" && body.Operator != pending.Operator {
		writeErr(w, http.StatusForbidden,
			"operator %q did not authorise this step (it was %q)", body.Operator, pending.Operator)
		return
	}

	// Condition 2: high-authorisation, ONLY when the deployment asks for it.
	//
	// ADR-006: on a single-operator, loopback, token-authenticated console the
	// human action that matters is the click on "approve". Requiring a second
	// cryptographic ritual on top of it made operators either give up or share a
	// weak key - which is *less* safe than one clear click. So the record is
	// optional by default and comes back verbatim when RequireHighAuth is set.
	//
	// What does NOT change: condition 1 (a real, unconsumed approval row bound to
	// this exact fingerprint) is still required, approval is still consumed before
	// anything runs, and there is still no batch form of this endpoint.
	targets := knownTargets(s.cfg.Dispatcher, ctx, eng.ID, it.Capability, it.Args)
	needsHighAuth := s.cfg.RequireHighAuth && (requiresHighAuth(it.Capability) || anyURL(targets))
	if needsHighAuth {
		if s.cfg.HighAuthKey == "" {
			writeErr(w, http.StatusPreconditionRequired,
				"tier-2 execution against a network target needs a verified high-auth record, but %s is not configured on the server",
				discipline.HighAuthKeyEnv)
			return
		}
		if strings.TrimSpace(body.HighAuthPath) == "" {
			writeErr(w, http.StatusPreconditionRequired,
				"high_auth_path is required for a network target: produce a signed record with the key only you hold")
			return
		}
		rec, err := discipline.LoadHighAuth(body.HighAuthPath)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		grant, err := rec.Verify(s.cfg.HighAuthKey, time.Now())
		if err != nil {
			writeErr(w, http.StatusForbidden, "%v", err)
			return
		}
		for _, t := range targets {
			if !looksLikeURL(t) {
				continue
			}
			if !grant.Covers(t) {
				writeErr(w, http.StatusForbidden, "high-auth record does not cover %q", discipline.HostOf(t))
				return
			}
		}
	}

	// Condition 3: the passport must actually allow what this capability does.
	//
	// Without this the capability refuses *after* the approval was consumed, which
	// burns the operator's single authorisation and leaves the intent stuck
	// (found by the v0.5 E2E walkthrough).
	if sw := requiredScopeSwitch(it.Capability); sw != "" {
		var passport discipline.Scope
		if len(eng.Scope) > 0 {
			_ = json.Unmarshal(eng.Scope, &passport)
		}
		if enabled, ok := scopeSwitchValue(passport, sw); !ok || !enabled {
			writeErr(w, http.StatusPreconditionRequired,
				"这个能力需要护照里的 %s=true,当前为 false:先放宽护照再执行(本次未消费批准)", sw)
			return
		}
	}

	// Consume now: every precondition holds, and the UPDATE is atomic, so two
	// concurrent requests cannot both get through.
	ap, err := s.cfg.Store.ConsumeApproval(ctx, eng.ID, iid)
	if err != nil {
		writeErr(w, http.StatusForbidden, "%v", err)
		return
	}

	if err := s.cfg.Store.SetIntentStatus(ctx, eng.ID, iid, ledger.StatusActive); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	started := time.Now()
	obs, derr := s.cfg.Dispatcher.Run(ctx, eng.ID, it.Capability, it.Args)
	elapsed := time.Since(started).Milliseconds()
	if derr != nil {
		msg := "capability failed: " + derr.Error()
		// Leaving the intent "active" would hide it from the workbench forever: it
		// is neither running nor waiting. Put it back in front of the human; the
		// approval was consumed, so re-approving is the explicit next step.
		_ = s.cfg.Store.SetIntentStatus(ctx, eng.ID, iid, ledger.StatusNeedsApproval)
		_ = s.cfg.Store.AppendTrace(ctx, eng.ID, iid, msg+" (approval consumed; fix the cause, then approve again)")
		writeErr(w, http.StatusBadGateway, "%s", msg)
		return
	}

	intentID := iid
	res, ierr := s.cfg.Store.Ingest(ctx, eng.ID, nil, &intentID, obs)
	if ierr != nil {
		writeErr(w, http.StatusInternalServerError, "ingest: %v", ierr)
		return
	}
	if err := s.cfg.Store.SetIntentStatus(ctx, eng.ID, iid, ledger.StatusDone); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	// A probe that was derived from a whitebox lead settles that lead here: the
	// tier-2 path executes through this route, not through the engine loop.
	if hid := engine.HypothesisIDOf(it.Args); hid > 0 {
		var store engine.Store = s.cfg.Store
		engine.ConfirmProbe(ctx, &store, eng.ID, hid, len(res.FindingIDs), obs.RequestIDs)
	}

	trace := fmt.Sprintf("human step executed: operator=%s basis=%q approval=%d capability=%s facts=%d findings=%d",
		ap.Operator, ap.Basis, ap.ID, it.Capability, res.NewFacts, len(res.FindingIDs))
	if len(obs.RequestIDs) > 0 {
		trace += " request_ids=" + strings.Join(obs.RequestIDs, ",")
	}
	_ = s.cfg.Store.AppendTrace(ctx, eng.ID, iid, trace)

	// A hand-approved step is a step too: narrate it into the same stream, so the
	// transcript does not have a hole exactly where the human intervened.
	{
		ev := engine.StepEvent{
			Phase: engine.PhaseExec, IntentID: iid, Capability: it.Capability,
			Tier: it.Tier, Target: engine.TargetForArgs(it.Args), Status: "ok",
			Facts: res.NewFacts, Findings: len(res.FindingIDs),
		}
		if len(obs.RequestIDs) > 0 {
			ev.RequestID = obs.RequestIDs[0]
		}
		if ev.Facts == 0 && ev.Findings == 0 {
			ev.Status = "miss"
			ev.Summary = "没有新证据"
		} else {
			ev.Summary = fmt.Sprintf("(人工批准后执行)得到 %d 条事实、%d 条候选", ev.Facts, ev.Findings)
		}
		s.narrate(eng.ID, ev)
	}
	s.hub.publish("approvals", map[string]any{"type": "executed", "intent_id": iid, "engagement": eng.Name})
	writeJSON(w, http.StatusOK, map[string]any{
		"intent_id":   iid,
		"capability":  it.Capability,
		"ok":          true,
		"facts":       res.NewFacts,
		"findings":    len(res.FindingIDs),
		"request_ids": obs.RequestIDs,
		"summary":     obs.Summary,
		"duration_ms": elapsed,
		"approval": map[string]any{
			"id": ap.ID, "operator": ap.Operator, "basis": ap.Basis,
			"high_auth_path": ap.HighAuthPath, "consumed_at": ap.ConsumedAt,
		},
		"next": "the approval is consumed; the next step needs a new proposal, a new approval, and a new high-auth record",
	})
}

// targetOf extracts what an intent would touch, for high-auth coverage.
func targetOf(capability string, args map[string]any) string {
	if args == nil {
		return ""
	}
	if u, ok := args["url"].(string); ok && u != "" {
		return u
	}
	if us, ok := args["urls"].([]any); ok && len(us) > 0 {
		if s, ok := us[0].(string); ok {
			return s
		}
	}
	if p, ok := args["path"].(string); ok && p != "" {
		return p
	}
	return ""
}

func looksLikeURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// ---- findings --------------------------------------------------------------

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request, eng ledger.Engagement, tail []string) {
	if len(tail) == 0 {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		list, err := s.cfg.Store.ListFindings(r.Context(), eng.ID, queryInt(r, "limit", 500))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}
	fid, err := parseID(tail[0])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad finding id")
		return
	}
	action := ""
	if len(tail) > 1 {
		action = tail[1]
	}
	switch action {
	case "verdict":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		var body struct {
			Operator string `json:"operator"`
			Note     string `json:"note"`
			Confirm  bool   `json:"confirm"`
		}
		if err := decodeJSON(w, r, &body); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		if !body.Confirm {
			writeErr(w, http.StatusBadRequest,
				"candidate -> verified requires an explicit operator confirmation (confirm=true)")
			return
		}
		f, err := s.cfg.Store.VerifyFinding(r.Context(), eng.ID, fid, body.Operator, body.Note)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, f)
	default:
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		f, err := s.cfg.Store.Finding(r.Context(), eng.ID, fid)
		if err != nil {
			writeErr(w, http.StatusNotFound, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, f)
	}
}

// networkCapabilities are the tier-2 capabilities that put bytes on the wire even
// when no URL appears in their arguments.
var networkCapabilities = map[string]bool{
	"param": true, "param_adaptive": true, "waf": true, "login": true,
	"accounts_provision": true, "accounts_seed": true, "object_seed": true,
	"accounts_register": true, "download": true, "reachability": true,
}

// requiresHighAuth reports whether a capability is network-facing by nature.
func requiresHighAuth(capability string) bool { return networkCapabilities[capability] }

// TargetResolver is implemented by a dispatcher that can name the targets a
// capability would touch (the account layer reads its manifest for this).
type TargetResolver interface {
	TargetsFor(ctx context.Context, engagementID int64, capability string, args map[string]any) []string
}

// knownTargets collects every target the API can attribute to an intent.
func knownTargets(d engine.Dispatcher, ctx context.Context, engagementID int64, capability string, args map[string]any) []string {
	var out []string
	if t := targetOf(capability, args); t != "" {
		out = append(out, t)
	}
	if tr, ok := d.(TargetResolver); ok {
		out = append(out, tr.TargetsFor(ctx, engagementID, capability, args)...)
	}
	return out
}

// anyURL reports whether at least one target looks like a network URL.
func anyURL(targets []string) bool {
	for _, t := range targets {
		if looksLikeURL(t) {
			return true
		}
	}
	return false
}

// requiredScopeSwitch names the passport switch a tier-2 capability needs.
//
// These are deliberately not folded into one "allow dangerous things" flag: each
// one unlocks a different class of action, so an operator widens exactly what they
// mean to.
func requiredScopeSwitch(capability string) string {
	switch capability {
	case "param", "param_adaptive":
		return "allow_active_probes"
	case "waf":
		return "allow_waf_probe"
	case "accounts_seed", "object_seed":
		return "allow_object_seeding"
	case "accounts_register":
		return "allow_account_provisioning"
	}
	return ""
}

// scopeSwitchValue reads a switch by name.
func scopeSwitchValue(s discipline.Scope, name string) (bool, bool) {
	switch name {
	case "allow_active_probes":
		return s.AllowActiveProbes, true
	case "allow_waf_probe":
		return s.AllowWAFProbe, true
	case "allow_object_seeding":
		return s.AllowObjectSeeding, true
	case "allow_account_provisioning":
		return s.AllowAccountProvisioning, true
	}
	return false, false
}

// retryIntent requeues a step that ended in "blocked".
//
// A blocked step means the last attempt failed (the target was down, a transient
// error, the scope changed). Without this it stays wedged forever: nothing claims
// it, and the fingerprint dedupe refuses to derive it again. Retrying does not
// loosen anything - a tier-1 step goes back into the autonomous queue and still
// passes the guard, and a tier-2 step goes back in front of a human, where it
// needs a fresh approval (the old one was consumed).
func (s *Server) retryIntent(w http.ResponseWriter, r *http.Request, eng ledger.Engagement, iid int64) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	it, err := s.cfg.Store.Intent(r.Context(), eng.ID, iid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "%v", err)
		return
	}
	if it.Status != ledger.StatusBlocked {
		writeErr(w, http.StatusBadRequest, "只有失败的步骤可以重试(当前状态 %s)", it.Status)
		return
	}
	next := ledger.StatusTodo
	tier := int(gate.Classify(it.Capability, it.Args))
	if tier >= 2 {
		next = ledger.StatusNeedsApproval
		// ...unless a signed mandate already covers it: then it belongs back in the
		// autonomous queue, not in front of a human who already said yes.
		if s.mandateCoversIntent(r, eng, it) {
			next = ledger.StatusTodo
		}
	}
	if err := s.cfg.Store.SetIntentStatus(r.Context(), eng.ID, iid, next); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	_ = s.cfg.Store.AppendTrace(r.Context(), eng.ID, iid, "requeued by operator (was blocked)")
	writeJSON(w, http.StatusOK, map[string]any{
		"intent_id": iid, "status": next,
		"next": "重新排队:只读步骤会在下一轮自己跑,高风险步骤要你重新批准",
	})
}

// rejectIntent closes the door on one step without running it.
//
// It exists because "approve / refuse" is the whole interaction the operator is
// being offered in the conversation panel: a refusal must be recorded, not just
// left hanging in needs_approval.
func (s *Server) rejectIntent(w http.ResponseWriter, r *http.Request, eng ledger.Engagement, iid int64) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var body struct {
		Operator string `json:"operator"`
		Reason   string `json:"reason"`
	}
	_ = decodeJSON(w, r, &body)
	it, err := s.cfg.Store.Intent(r.Context(), eng.ID, iid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "%v", err)
		return
	}
	if it.Status == ledger.StatusDone || it.Status == ledger.StatusActive {
		writeErr(w, http.StatusBadRequest, "这一步已经执行过了,不能拒绝")
		return
	}
	if err := s.cfg.Store.SetIntentStatus(r.Context(), eng.ID, iid, ledger.StatusBlocked); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	line := "operator refused this step"
	if body.Operator != "" {
		line += " (" + body.Operator + ")"
	}
	if body.Reason != "" {
		line += ": " + body.Reason
	}
	_ = s.cfg.Store.AppendTrace(r.Context(), eng.ID, iid, line)
	writeJSON(w, http.StatusOK, map[string]any{"intent_id": iid, "status": ledger.StatusBlocked})
}
