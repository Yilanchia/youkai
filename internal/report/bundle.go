// Package report turns the ledger into deliverables a third party can check.
//
// The rule that shapes every file here: a report is a PROJECTION of the ledger,
// never a second source of truth. Nothing in this package sends a request, reads a
// target, or consults the gate - data in, text out. Two consequences fall out of
// that:
//
//   - the same ledger renders to the same bytes (snapshots are checkable by hash);
//   - a finding that cannot cite an audit row is visibly incomplete rather than
//     quietly dropped or quietly trusted.
//
// Every finding must carry four things (Proof-Carrying Pentest): evidence
// (request ids that resolve to audit rows), the minimum impact of the action that
// produced it, the stop condition that bounded it, and the counter-argument (why it
// could be wrong). Missing any of them is reported as `incomplete:<what>`, and an
// incomplete finding is never disclosable.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"youkai/internal/ledger"
	"youkai/internal/wording"
)

// Schema identifies the bundle format.
const Schema = "YoukaiReport/v1"

// The audit verdict vocabulary, restated here so this package stays free of
// imports that could reach the network.
const (
	verdictAllowed = "allowed"
	verdictBlocked = "blocked"
)

// Bundle is the report: the ledger, graded.
type Bundle struct {
	Schema      string            `json:"schema"`
	Engagement  string            `json:"engagement"`
	GeneratedAt string            `json:"generated_at"`
	Scope       json.RawMessage   `json:"scope"`
	Provider    string            `json:"exploit_provider"`
	Stats       ledger.GraphStats `json:"stats"`
	Coverage    Coverage          `json:"coverage"`
	Findings    []FindingReport   `json:"findings"`
	Facts       []ledger.Fact     `json:"facts"`
	Intents     []IntentReport    `json:"intents"`
	Audit       []ledger.AuditRow `json:"audit"`
	// Incomplete lists every finding that is missing one of the four evidence
	// pieces, in the form "finding #12: counter".
	Incomplete []string `json:"incomplete,omitempty"`
}

// Coverage is the honest statement of what was actually touched. It is computed
// from audit rows, never from the scope: the passport says where youkai MAY look,
// the audit says where it DID.
type Coverage struct {
	Requests  int      `json:"requests"`
	Allowed   int      `json:"allowed"`
	Blocked   int      `json:"blocked"`
	Failed    int      `json:"failed"`
	Hosts     []string `json:"hosts"`
	Endpoints int      `json:"endpoints"`
	// EndpointList is the (method, path) pairs actually requested, sorted.
	EndpointList []string `json:"endpoint_list"`
	// FindingsByKind counts candidates per kind.
	FindingsByKind map[string]int `json:"findings_by_kind"`
	Statement      string         `json:"statement"`
}

// Evidence is the first of the four: what actually happened, and where to check it.
type Evidence struct {
	// RequestIDs are the audit anchors the finding cites.
	RequestIDs []string `json:"request_ids"`
	// Audit rows resolved from those ids (the proof the request existed).
	Audit []ledger.AuditRow `json:"audit,omitempty"`
	// Missing are cited ids with no audit row: the finding claims an event that
	// cannot be located.
	Missing []string `json:"missing,omitempty"`
	// BlockedIDs are cited ids whose audit verdict is not "allowed". They are still
	// evidence (an attempt was refused), but the report says so.
	BlockedIDs []string `json:"blocked,omitempty"`
	// Complete is true when at least one id is cited and none is missing.
	Complete bool `json:"complete"`
}

// FindingReport is one finding plus its four evidence pieces.
type FindingReport struct {
	ledger.Finding
	Evidence      Evidence `json:"evidence_block"`
	MinImpact     string   `json:"min_impact"`
	StopCondition string   `json:"stop_condition"`
	Counter       string   `json:"counter"`
	// Incomplete names the missing pieces ("evidence", "min_impact",
	// "stop_condition", "counter").
	Incomplete []string `json:"incomplete,omitempty"`
	// Disclosable is true for verified findings with all four pieces present.
	Disclosable bool `json:"disclosable"`
	// Capability is the action behind the finding, derived from the audit purpose.
	Capability string `json:"capability,omitempty"`
	// Remediation is how to fix it: generic best practice, safe to hand to the owner.
	// Empty for kinds we have no specific advice for - a blank beats a guess.
	Remediation string `json:"remediation,omitempty"`
}

// IntentReport is one intent plus the wording that bounded it.
type IntentReport struct {
	ledger.Intent
	MinImpact     string `json:"min_impact"`
	StopCondition string `json:"stop_condition"`
}

// Input is everything Build needs; the caller (the API) reads the ledger.
type Input struct {
	Engagement string
	Scope      json.RawMessage
	Provider   string
	Stats      ledger.GraphStats
	Findings   []ledger.Finding
	Facts      []ledger.Fact
	Intents    []ledger.Intent
	Audit      []ledger.AuditRow
	// GeneratedAt is injected so rendering is deterministic; when empty Build
	// derives it from the newest audit row (and falls back to the zero time).
	GeneratedAt string
}

// Build assembles the bundle and grades every finding.
func Build(in Input) Bundle {
	byRequest := make(map[string]ledger.AuditRow, len(in.Audit))
	for _, a := range in.Audit {
		byRequest[a.RequestID] = a
	}

	b := Bundle{
		Schema:      Schema,
		Engagement:  in.Engagement,
		GeneratedAt: in.GeneratedAt,
		Scope:       in.Scope,
		Provider:    in.Provider,
		Stats:       in.Stats,
		Facts:       nonNilFacts(in.Facts),
		Audit:       nonNilAudit(in.Audit),
		Coverage:    buildCoverage(in.Audit, in.Findings),
	}
	if b.GeneratedAt == "" {
		b.GeneratedAt = newestAuditTS(in.Audit)
	}
	if len(b.Scope) == 0 {
		b.Scope = json.RawMessage(`{}`)
	}

	for _, it := range in.Intents {
		b.Intents = append(b.Intents, IntentReport{
			Intent:        it,
			MinImpact:     wording.MinImpact(it.Capability),
			StopCondition: wording.StopCondition(it.Capability),
		})
	}

	for _, f := range in.Findings {
		fr := gradeFinding(f, byRequest)
		if len(fr.Incomplete) > 0 {
			b.Incomplete = append(b.Incomplete, fmt.Sprintf("finding #%d: %s", f.ID, strings.Join(fr.Incomplete, ",")))
		}
		b.Findings = append(b.Findings, fr)
	}
	sort.SliceStable(b.Incomplete, func(i, j int) bool { return b.Incomplete[i] < b.Incomplete[j] })
	return b
}

// gradeFinding checks the four pieces and fills what can be derived honestly.
func gradeFinding(f ledger.Finding, audit map[string]ledger.AuditRow) FindingReport {
	fr := FindingReport{Finding: f}
	fr.Remediation = RemediationFor(f.Kind)
	fr.Evidence.RequestIDs = requestIDsOf(f.Evidence)
	for _, id := range fr.Evidence.RequestIDs {
		if id == "" {
			continue
		}
		row, ok := audit[id]
		if !ok {
			fr.Evidence.Missing = append(fr.Evidence.Missing, id)
			continue
		}
		fr.Evidence.Audit = append(fr.Evidence.Audit, row)
		if row.Verdict != verdictAllowed {
			fr.Evidence.BlockedIDs = append(fr.Evidence.BlockedIDs, id)
		}
		if fr.Capability == "" {
			fr.Capability = capabilityOfPurpose(row.Purpose)
		}
	}
	fr.Evidence.Complete = len(fr.Evidence.RequestIDs) > 0 && len(fr.Evidence.Missing) == 0
	if !fr.Evidence.Complete {
		fr.Incomplete = append(fr.Incomplete, "evidence")
	}

	// Minimum impact and stop condition come from the capability that produced it;
	// when the capability is unknown the wording package says so rather than
	// pretending a default is a measurement.
	fr.MinImpact = wording.MinImpact(fr.Capability)
	fr.StopCondition = wording.StopCondition(fr.Capability)
	if strings.HasPrefix(fr.MinImpact, "unknown") {
		fr.Incomplete = append(fr.Incomplete, "min_impact")
	}
	if strings.TrimSpace(fr.StopCondition) == "" {
		fr.Incomplete = append(fr.Incomplete, "stop_condition")
	}

	// The counter-argument: the finding's own, else a template by kind. An unknown
	// kind with no counter stays missing - silence is not an argument.
	fr.Counter = strings.TrimSpace(f.Counter)
	if fr.Counter == "" {
		fr.Counter = counterFor(f.Kind)
	}
	if fr.Counter == "" {
		fr.Incomplete = append(fr.Incomplete, "counter")
	}

	fr.Disclosable = f.State == ledger.FindingVerified && len(fr.Incomplete) == 0
	return fr
}

// buildCoverage projects the audit log into "what was actually touched".
func buildCoverage(audit []ledger.AuditRow, findings []ledger.Finding) Coverage {
	cov := Coverage{FindingsByKind: map[string]int{}}
	hosts := map[string]bool{}
	endpoints := map[string]bool{}
	for _, a := range audit {
		cov.Requests++
		switch a.Verdict {
		case verdictAllowed:
			cov.Allowed++
		case verdictBlocked:
			cov.Blocked++
		default:
			cov.Failed++
		}
		if a.Host != "" {
			hosts[a.Host] = true
		}
		if a.URL != "" {
			endpoints[a.Method+" "+endpointPath(a.URL)] = true
		}
	}
	for _, f := range findings {
		cov.FindingsByKind[f.Kind]++
	}
	cov.Hosts = sortedKeys(hosts)
	cov.EndpointList = sortedKeys(endpoints)
	cov.Endpoints = len(cov.EndpointList)
	if cov.Requests == 0 {
		cov.Statement = "覆盖:尚未发出任何请求 —— 本报告没有可声明覆盖的目标。"
	} else {
		cov.Statement = fmt.Sprintf(
			"覆盖:实际测过 %d 个主机、%d 个端点(共 %d 次请求,允许 %d / 阻断 %d / 失败 %d);未在此列出的资产不在本报告范围内。",
			len(cov.Hosts), cov.Endpoints, cov.Requests, cov.Allowed, cov.Blocked, cov.Failed)
	}
	return cov
}

// Hash returns the snapshot anchor: sha256 over the canonical JSON.
//
// encoding/json sorts map keys and emits structs in field order, so the same
// bundle always hashes the same way.
func Hash(b Bundle) (string, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("report: canonicalise bundle: %w", err)
	}
	return sha256Hex(raw), nil
}

// ---- helpers ---------------------------------------------------------------

func requestIDsOf(evidence map[string]any) []string {
	if evidence == nil {
		return nil
	}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		for _, e := range out {
			if e == s {
				return
			}
		}
		out = append(out, s)
	}
	switch v := evidence["request_id"].(type) {
	case string:
		add(v)
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				add(s)
			}
		}
	case []string:
		for _, s := range v {
			add(s)
		}
	}
	if ids, ok := evidence["request_ids"]; ok {
		switch v := ids.(type) {
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					add(s)
				}
			}
		case []string:
			for _, s := range v {
				add(s)
			}
		case string:
			add(v)
		}
	}
	sort.Strings(out)
	return out
}

// capabilityOfPurpose maps an audit purpose ("probe", "compare:a", "browser") to a
// capability name.
func capabilityOfPurpose(purpose string) string {
	if i := strings.IndexByte(purpose, ':'); i > 0 {
		return purpose[:i]
	}
	return purpose
}

func endpointPath(rawURL string) string {
	// Keep the scheme-less host+path so two hosts do not collapse; drop the query
	// (it is where markers and parameters live) so the count is stable.
	withoutScheme := rawURL
	if i := strings.Index(withoutScheme, "://"); i >= 0 {
		withoutScheme = withoutScheme[i+3:]
	}
	if i := strings.IndexByte(withoutScheme, '?'); i >= 0 {
		withoutScheme = withoutScheme[:i]
	}
	if i := strings.IndexByte(withoutScheme, '#'); i >= 0 {
		withoutScheme = withoutScheme[:i]
	}
	return withoutScheme
}

func newestAuditTS(audit []ledger.AuditRow) string {
	var latest time.Time
	for _, a := range audit {
		if a.TS.After(latest) {
			latest = a.TS
		}
	}
	if latest.IsZero() {
		return ""
	}
	return latest.UTC().Format(time.RFC3339)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func nonNilFacts(in []ledger.Fact) []ledger.Fact {
	if in == nil {
		return []ledger.Fact{}
	}
	return in
}

func nonNilAudit(in []ledger.AuditRow) []ledger.AuditRow {
	if in == nil {
		return []ledger.AuditRow{}
	}
	return in
}
