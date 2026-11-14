package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"youkai/internal/discipline"
	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// Mandates (ADR-005): the one place where tier-2 work can run without a per-step
// approval. Three endpoints, and each of them is deliberately boring:
//
//	GET  …/mandate           what is in force right now (no caching)
//	POST …/mandate/activate  verify a HUMAN-SIGNED record and store it
//	POST …/mandate/stop      revoke immediately
//
// Youkai never signs. `activate` only accepts a record whose signature verifies
// against FAIRY_AUTH_KEY, a key this process can read but never write, and which
// is never stored.

func (s *Server) handleMandate(w http.ResponseWriter, r *http.Request, eng ledger.Engagement, tail []string) {
	switch {
	case len(tail) == 0 && r.Method == http.MethodGet:
		m, err := s.cfg.Store.ActiveMandate(r.Context(), eng.ID)
		if err == ledger.ErrNotFound {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		used, _ := s.cfg.Store.MandateUsage(r.Context(), eng.Name, m.ActivatedAt)
		writeJSON(w, http.StatusOK, map[string]any{
			"active": true, "mandate": m, "used": used,
			"remaining": m.MaxRequests - used,
		})
	case len(tail) == 1 && tail[0] == "activate" && r.Method == http.MethodPost:
		s.activateMandate(w, r, eng)
	case len(tail) == 1 && tail[0] == "stop" && r.Method == http.MethodPost:
		n, err := s.cfg.Store.StopMandate(r.Context(), eng.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		s.trace(r, eng.ID, "mandate revoked by operator: tier-2 work returns to one-at-a-time approval")
		writeJSON(w, http.StatusOK, map[string]any{
			"stopped": n, "next": "已撤销:高风险动作回到逐步审批,正在跑的只读步骤不受影响",
		})
	default:
		writeErr(w, http.StatusNotFound, "use GET …, POST …/activate, POST …/stop")
	}
}

// activateMandate verifies a signed record and stores it.
func (s *Server) activateMandate(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	key, err := discipline.KeyFromEnv()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "%v", err)
		return
	}
	var record discipline.HighAuth
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&record); err != nil {
		writeErr(w, http.StatusBadRequest, "无法解析签名记录:%v", err)
		return
	}
	known := []string{gate.ClassParam, gate.ClassWAF, gate.ClassSeeding, gate.ClassRegistration}
	grant, classes, err := record.VerifyMandate(key, time.Now(), known)
	if err != nil {
		// Verbatim: the operator needs to know which field failed.
		writeErr(w, http.StatusForbidden, "签名未通过:%v", err)
		return
	}
	if len(classes) == 0 {
		writeErr(w, http.StatusBadRequest, "这份委托书没有授权任何高风险动作类")
		return
	}
	maxReq, ok := intField(record.Payload, "max_requests")
	if !ok || maxReq <= 0 {
		writeErr(w, http.StatusBadRequest, "委托书缺少请求上限(max_requests);没有上限的委托书不会被接受")
		return
	}
	// Each class also has to be switched on in the passport. Two fences, and the
	// narrower one wins: a mandate says "you may stop asking me", not "you may do
	// what this engagement forbids". Saying so at activation beats a silent stall
	// three steps into a run.
	for _, class := range classes {
		if !scopeSwitchOn(eng, class) {
			writeErr(w, http.StatusForbidden,
				"这个任务的授权范围没有打开 %s 对应的开关(%s);先在「编辑授权范围」里打开,再签委托书",
				class, switchForClass(class))
			return
		}
	}

	// The mandate's assets must be inside the passport. A signature cannot widen
	// the scope; it can only narrow what happens within it.
	for _, asset := range grant.Assets {
		if !scopeAllows(eng, asset) {
			writeErr(w, http.StatusForbidden, "委托书里的目标 %q 不在当前授权范围内", asset)
			return
		}
	}
	payload, err := json.Marshal(record.Payload)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	m, err := s.cfg.Store.SaveMandate(r.Context(), eng.ID, payload, record.Signature,
		grant.Assets, classes, maxReq, grant.ExpiresAt, grant.Approver, grant.Basis)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	s.trace(r, eng.ID, "mandate activated: classes="+strings.Join(classes, ",")+
		" targets="+strings.Join(grant.Assets, ",")+
		" budget="+strconv.Itoa(maxReq)+" expires="+grant.ExpiresAt.Format(time.RFC3339))
	writeJSON(w, http.StatusCreated, map[string]any{
		"mandate": m, "classes": classes, "used": 0, "remaining": maxReq,
		"next": "委托书已生效:这些动作类会自己跑,直到上限、到期,或你摁急停",
	})
}

// scopeAllows reports whether an asset named by a mandate is inside the passport.
//
// The rule, deliberately narrow: the host must match, and if the mandate names a
// port that port must match too. A bare host covers every port on that host -
// which is exactly what the engine will enforce, so activation can never accept
// something the engine would refuse (or vice versa).
func scopeAllows(eng ledger.Engagement, asset string) bool {
	var sc map[string]any
	if err := json.Unmarshal(eng.Scope, &sc); err != nil {
		return false
	}
	aHost, aPort := splitHostPort(asset)
	if aHost == "" {
		return false
	}
	raw, _ := sc["include"].([]any)
	for _, item := range raw {
		inc, _ := item.(string)
		hHost, hPort := splitHostPort(inc)
		if hHost == "" || hHost != aHost {
			continue
		}
		if aPort == "" || aPort == hPort {
			return true
		}
	}
	return false
}

// splitHostPort returns the hostname and port of a URL, a host, a host:port, or a
// path, ignoring scheme, userinfo, and trailing slashes.
func splitHostPort(v string) (string, string) {
	t := strings.ToLower(strings.TrimSpace(v))
	if t == "" {
		return "", ""
	}
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.Index(t, "@"); i >= 0 {
		t = t[i+1:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	host, port := t, ""
	if strings.HasPrefix(host, "[") { // IPv6 literal
		if j := strings.Index(host, "]"); j > 0 {
			port = strings.TrimPrefix(host[j+1:], ":")
			host = host[1:j]
		}
	} else if i := strings.LastIndex(host, ":"); i > 0 {
		port = host[i+1:]
		host = host[:i]
	}
	return strings.TrimSuffix(host, "."), port
}
func intField(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

// trace appends a line to the engagement's run trail (best effort).
func (s *Server) trace(r *http.Request, engagementID int64, line string) {
	_ = s.cfg.Store.AppendTrace(r.Context(), engagementID, 0, line)
}

// sortedUnique is a small helper for stable output in tests and logs.
func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// switchForClass names the passport switch a mandate class depends on.
func switchForClass(class string) string {
	switch class {
	case gate.ClassParam:
		return "allow_active_probes"
	case gate.ClassWAF:
		return "allow_waf_probe"
	case gate.ClassSeeding:
		return "allow_object_seeding"
	case gate.ClassRegistration:
		return "allow_account_provisioning"
	}
	return ""
}

// scopeSwitchOn reports whether the passport enables a class.
func scopeSwitchOn(eng ledger.Engagement, class string) bool {
	sw := switchForClass(class)
	if sw == "" {
		return false
	}
	var sc map[string]any
	if err := json.Unmarshal(eng.Scope, &sc); err != nil {
		return false
	}
	on, _ := sc[sw].(bool)
	return on
}

// mandateCoversIntent reports whether the mandate in force authorises this step.
//
// Used by retry so a covered step returns to the autonomous queue instead of
// asking a human to approve something a human already pre-authorised.
func (s *Server) mandateCoversIntent(r *http.Request, eng ledger.Engagement, it ledger.Intent) bool {
	m, err := s.cfg.Store.ActiveMandate(r.Context(), eng.ID)
	if err != nil || !m.Active(time.Now()) {
		return false
	}
	class := gate.AutonomyClass(it.Capability)
	if class == "" || !m.CoversClass(class) {
		return false
	}
	target, _ := it.Args["url"].(string)
	if target == "" {
		return false
	}
	host, _ := splitHostPort(target)
	for _, asset := range m.Assets {
		aHost, aPort := splitHostPort(asset)
		if aHost == host && (aPort == "" || aPort == mustPort(target)) {
			return true
		}
	}
	return false
}

// mustPort returns the explicit port of a URL, or "".
func mustPort(raw string) string {
	_, p := splitHostPort(raw)
	return p
}
