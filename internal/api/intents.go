package api

import (
	"context"
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
	dec := gate.Explain(body.Capability, body.Args)
	spec := ledger.IntentSpec{
		Capability:       body.Capability,
		Args:             body.Args,
		Tier:             int(dec.Tier),
		Rationale:        body.Rationale,
		ExpectedFact:     body.Expected,
		GateReason:       dec.Reason,
		RequiresApproval: dec.Tier.NeedsHuman(),
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
	nonce := ""
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
// Two independent human conditions must both hold, and the approval is consumed
// atomically before anything runs:
//  1. an unconsumed operator approval whose fingerprint matches this intent
//  2. for a network target, a valid high-auth record covering that target
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

	// Condition 2: high-authorisation for anything that leaves the machine.
	//
	// The target is not always in the arguments: an account capability names its
	// targets in the manifest, so a resolver supplies them. A capability that is
	// network-facing by nature needs the record even when no URL is derivable -
	// "we could not work out the target" must never mean "skip the check".
	targets := knownTargets(s.cfg.Dispatcher, ctx, eng.ID, it.Capability, it.Args)
	needsHighAuth := requiresHighAuth(it.Capability) || anyURL(targets)
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

	// Consume now: both preconditions hold, and the UPDATE is atomic, so two
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
		_ = s.cfg.Store.AppendTrace(ctx, eng.ID, iid, msg+" (approval already consumed; no retry)")
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
	trace := fmt.Sprintf("human step executed: operator=%s basis=%q approval=%d capability=%s facts=%d findings=%d",
		ap.Operator, ap.Basis, ap.ID, it.Capability, res.NewFacts, len(res.FindingIDs))
	if len(obs.RequestIDs) > 0 {
		trace += " request_ids=" + strings.Join(obs.RequestIDs, ",")
	}
	_ = s.cfg.Store.AppendTrace(ctx, eng.ID, iid, trace)

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
