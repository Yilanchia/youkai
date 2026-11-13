package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"youkai/internal/discipline"
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
	target := targetOf(it.Capability, it.Args)
	needsHighAuth := target != "" && looksLikeURL(target)
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
		if !grant.Covers(target) {
			writeErr(w, http.StatusForbidden, "high-auth record does not cover %q", target)
			return
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

// ---- report ----------------------------------------------------------------

// ReportBundle is the evidence report: the ledger is the source of truth, so the
// report is a projection of it, always reproducible.
type ReportBundle struct {
	Engagement  string            `json:"engagement"`
	GeneratedAt string            `json:"generated_at"`
	Scope       json.RawMessage   `json:"scope"`
	Stats       ledger.GraphStats `json:"stats"`
	Findings    []ledger.Finding  `json:"findings"`
	Facts       []ledger.Fact     `json:"facts"`
	Intents     []ledger.Intent   `json:"intents"`
	Audit       []ledger.AuditRow `json:"audit"`
	Provider    string            `json:"exploit_provider"`
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	g, err := s.cfg.Store.Graph(r.Context(), eng.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	audit, _ := s.cfg.Store.AuditTail(r.Context(), eng.Name, 500)
	bundle := ReportBundle{
		Engagement:  eng.Name,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Scope:       eng.Scope,
		Stats:       g.Stats,
		Findings:    g.Findings,
		Facts:       g.Facts,
		Intents:     g.Intents,
		Audit:       audit,
		Provider:    gate.Provider().Reason(),
	}
	if r.URL.Query().Get("format") == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(renderMarkdown(bundle)))
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

// renderMarkdown produces the human report. Every finding carries the four
// evidence fields; none of them is optional.
func renderMarkdown(b ReportBundle) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# youkai 证据报告 — %s\n\n生成时间:%s\n\n", b.Engagement, b.GeneratedAt)
	fmt.Fprintf(&sb, "- 资产 %d / 事实 %d / 发现 %d(已确认 %d)\n", b.Stats.Assets, b.Stats.Facts, b.Stats.Findings, b.Stats.Verified)
	fmt.Fprintf(&sb, "- 请求:允许 %d / 阻断 %d / 失败 %d\n", b.Stats.AuditAllowed, b.Stats.AuditBlocked, b.Stats.AuditError)
	fmt.Fprintf(&sb, "- 利用提供者:%s\n\n", b.Provider)

	sb.WriteString("## 发现\n\n")
	if len(b.Findings) == 0 {
		sb.WriteString("(无)\n\n")
	}
	for _, f := range b.Findings {
		reqID, _ := f.Evidence["request_id"].(string)
		fmt.Fprintf(&sb, "### [%s] %s\n\n", f.Severity, f.Title)
		fmt.Fprintf(&sb, "- 状态:**%s**\n", f.State)
		fmt.Fprintf(&sb, "- 位置:`%s`\n", f.Where)
		fmt.Fprintf(&sb, "- 证据:%s\n", emptyDash("request_id="+reqID))
		fmt.Fprintf(&sb, "- 反证/限制:%s\n", emptyDash(f.Detail))
		if f.Operator != "" {
			fmt.Fprintf(&sb, "- 操作员判定:%s(%s)\n", f.Operator, f.VerdictNote)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## 事实\n\n")
	for _, f := range b.Facts {
		reqID, _ := f.Evidence["request_id"].(string)
		fmt.Fprintf(&sb, "- [%s] %s%s\n", strings.Join(f.Tags, ","), f.Statement, ifSet(" (request_id="+reqID+")"))
	}
	sb.WriteString("\n## 意图与审批\n\n")
	for _, it := range b.Intents {
		fmt.Fprintf(&sb, "- #%d `%s` tier=%d status=%s approved=%v\n", it.ID, it.Capability, it.Tier, it.Status, it.Approved)
	}
	sb.WriteString("\n## 审计(最近)\n\n")
	for _, a := range b.Audit {
		fmt.Fprintf(&sb, "- %s %s %s → %d [%s] %s\n", a.TS.Format(time.RFC3339), a.Method, a.URL, a.Status, a.Verdict, a.Reason)
	}
	sb.WriteString("\n---\n本报告由账本投影生成,不含响应正文与凭据。\n")
	return sb.String()
}

func emptyDash(s string) string {
	if strings.TrimSpace(strings.TrimPrefix(s, "request_id=")) == "" {
		return "—"
	}
	return s
}

func ifSet(s string) string {
	if strings.TrimPrefix(strings.TrimSuffix(s, ")"), " (request_id=") == "" {
		return ""
	}
	return s
}
