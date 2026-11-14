package api

import (
	"encoding/json"
	"net/http"
	"reflect"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// Scope editing.
//
// The passport is the one thing standing between youkai and an unauthorised
// target, so widening it is a security action:
//
//   - every save is validated by the same rules the guard applies at request time
//     (no empty include, no `*`, no `*.tld`, basis length, not expired);
//   - every save writes an audit row with the before/after boundary, so "who
//     widened this engagement, when" is answerable later;
//   - a save never touches findings, intents or the exploitation wall. It changes
//     where youkai may look, not what it may do there.

// handleScope serves PUT /api/engagements/{id}/scope.
func (s *Server) handleScope(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	if r.Method != http.MethodPut {
		writeErr(w, http.StatusMethodNotAllowed, "PUT only")
		return
	}
	var body struct {
		Scope     json.RawMessage `json:"scope"`
		UpdatedBy string          `json:"updated_by"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if len(body.Scope) == 0 {
		writeErr(w, http.StatusBadRequest, "scope is required")
		return
	}
	var next discipline.Scope
	if err := json.Unmarshal(body.Scope, &next); err != nil {
		writeErr(w, http.StatusBadRequest, "scope: %v", err)
		return
	}
	normalised := discipline.NewScope(next)
	if err := normalised.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "scope: %v", err)
		return
	}

	// The old passport, for the audit detail and the response.
	var before discipline.Scope
	if len(eng.Scope) > 0 {
		_ = json.Unmarshal(eng.Scope, &before)
	}
	if reflect.DeepEqual(before, *normalised) {
		writeJSON(w, http.StatusOK, map[string]any{"engagement": eng, "changed": false})
		return
	}

	updated, err := s.cfg.Store.UpdateScope(r.Context(), eng.ID, *normalised)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if err := s.cfg.Store.RecordConfigChange(r.Context(), eng.Name, byOr(body.UpdatedBy, "operator"),
		"scope", scopeAudit(before), scopeAudit(*normalised)); err != nil {
		writeErr(w, http.StatusInternalServerError, "scope 已更新,但审计写入失败:%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"engagement": updated,
		"changed":    true,
		"widened":    widened(before, *normalised),
	})
}

// scopeAudit is the auditable projection of a passport: targets, method set and
// the switches that unlock tier-2 capabilities. It carries no secret, which is why
// the whole thing can go into the audit detail.
func scopeAudit(s discipline.Scope) map[string]any {
	return map[string]any{
		"include":                    s.Include,
		"exclude":                    s.Exclude,
		"methods":                    s.Methods,
		"allow_private":              s.AllowPrivate,
		"allow_active_probes":        s.AllowActiveProbes,
		"allow_waf_probe":            s.AllowWAFProbe,
		"allow_object_seeding":       s.AllowObjectSeeding,
		"allow_account_provisioning": s.AllowAccountProvisioning,
		"max_requests":               s.MaxRequests,
		"rps":                        s.RPS,
		"expires_at":                 s.ExpiresAt,
		"basis":                      s.Basis,
		"operator":                   s.Operator,
	}
}

// widened reports whether the new passport grants more than the old one.
//
// It is a summary for the UI ("this change widened the scope"), not an
// enforcement decision: the guard's per-request check is the real gate, and the
// human approval of tier-2 steps is unaffected.
func widened(before, after discipline.Scope) bool {
	addTargets := len(after.Include) > len(before.Include)
	addMethods := len(after.Methods) > len(before.Methods)
	switches := (!before.AllowActiveProbes && after.AllowActiveProbes) ||
		(!before.AllowWAFProbe && after.AllowWAFProbe) ||
		(!before.AllowObjectSeeding && after.AllowObjectSeeding) ||
		(!before.AllowAccountProvisioning && after.AllowAccountProvisioning) ||
		(!before.AllowPrivate && after.AllowPrivate)
	return addTargets || addMethods || switches
}
