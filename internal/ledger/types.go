// Package ledger is youkai's truth: the asset graph, the exploration graph, the
// append-only audit trail, and the intent lifecycle - all in PostgreSQL.
//
// ADR-004 merged Fairy's authority into youkai, so this package is now the only
// authority. Two guarantees are enforced by database triggers rather than by
// convention (see schema.sql): audit_log cannot be changed, and neither a
// verified finding nor an approved intent can be written without the matching
// human act in the same transaction.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Node kinds, kept as strings so the graph view can be joined across tables.
const (
	KindAsset   = "asset"
	KindFact    = "fact"
	KindFinding = "finding"
	KindIntent  = "intent"
)

// Relations for the lineage graph.
const (
	RelDerives   = "derives"
	RelDependsOn = "depends_on"
	RelAnchors   = "anchors"
	RelSupports  = "supports"
	RelRefutes   = "refutes"
)

// Intent lifecycle.
const (
	StatusTodo          = "todo"
	StatusActive        = "active"
	StatusDone          = "done"
	StatusSkipped       = "skipped"
	StatusBlocked       = "blocked"
	StatusNeedsApproval = "needs_approval"
)

// Finding states.
const (
	FindingCandidate    = "candidate"
	FindingVerified     = "verified"
	FindingFalsePos     = "false-positive"
	FindingRemediated   = "remediated"
	FindingAcceptedRisk = "accepted-risk"
)

// Engagement is a scope-bound piece of work. Every row hangs off one.
type Engagement struct {
	ID        int64           `json:"id"`
	Name      string          `json:"name"`
	Scope     json.RawMessage `json:"scope"`
	CreatedAt time.Time       `json:"created_at"`
}

// Asset is one vertex of the asset graph: host, surface, artifact, endpoint.
type Asset struct {
	ID           int64          `json:"id"`
	EngagementID int64          `json:"engagement_id"`
	Kind         string         `json:"kind"`
	Value        string         `json:"value"`
	Props        map[string]any `json:"props"`
	CreatedAt    time.Time      `json:"created_at"`
}

// Fact is a normalised observation. Statements are short, evidence points at a
// request_id and/or an audit location. Response bodies never become facts.
type Fact struct {
	ID           int64          `json:"id"`
	EngagementID int64          `json:"engagement_id"`
	Statement    string         `json:"statement"`
	Evidence     map[string]any `json:"evidence"`
	Tags         []string       `json:"tags"`
	State        string         `json:"state"`
	RunID        *int64         `json:"run_id,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// Finding is a candidate vulnerability. It starts as a candidate, always.
type Finding struct {
	ID           int64          `json:"id"`
	EngagementID int64          `json:"engagement_id"`
	Title        string         `json:"title"`
	Severity     string         `json:"severity"`
	Kind         string         `json:"kind"`
	Where        string         `json:"where"`
	Detail       string         `json:"detail"`
	State        string         `json:"state"`
	Evidence     map[string]any `json:"evidence"`
	Tags         []string       `json:"tags"`
	Operator     string         `json:"operator,omitempty"`
	VerdictNote  string         `json:"verdict_note,omitempty"`
	VerifiedAt   *time.Time     `json:"verified_at,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// Intent is one typed next step. Approval is a human act recorded elsewhere.
type Intent struct {
	ID               int64          `json:"id"`
	EngagementID     int64          `json:"engagement_id"`
	Capability       string         `json:"capability"`
	Args             map[string]any `json:"args"`
	Tier             int            `json:"tier"`
	Status           string         `json:"status"`
	RequiresApproval bool           `json:"requires_approval"`
	Approved         bool           `json:"approved"`
	Fingerprint      string         `json:"fingerprint"`
	Rationale        string         `json:"rationale"`
	ExpectedFact     string         `json:"expected_fact"`
	Provenance       string         `json:"provenance"`
	Inferred         bool           `json:"inferred"`
	GateReason       string         `json:"gate_reason"`
	Trace            string         `json:"trace"`
	Deps             []int64        `json:"deps"`
	CreatedAt        time.Time      `json:"created_at"`
}

// Approval is an operator's single-use authorisation of one intent.
type Approval struct {
	ID            int64      `json:"id"`
	IntentID      int64      `json:"intent_id"`
	Fingerprint   string     `json:"fingerprint"`
	Operator      string     `json:"operator"`
	Basis         string     `json:"basis"`
	HighAuthPath  string     `json:"high_auth_path"`
	HighAuthNonce string     `json:"high_auth_nonce"`
	CreatedAt     time.Time  `json:"created_at"`
	ConsumedAt    *time.Time `json:"consumed_at,omitempty"`
}

// Run is one bounded engine run.
type Run struct {
	ID           int64          `json:"id"`
	EngagementID int64          `json:"engagement_id"`
	Status       string         `json:"status"`
	StopReason   string         `json:"stop_reason"`
	Steps        int            `json:"steps"`
	Derived      int            `json:"derived"`
	Config       map[string]any `json:"config"`
	StartedAt    time.Time      `json:"started_at"`
	EndedAt      *time.Time     `json:"ended_at,omitempty"`
}

// AuditRow is one immutable request record, as read back for the UI.
type AuditRow struct {
	ID         int64          `json:"id"`
	Engagement string         `json:"engagement"`
	RequestID  string         `json:"request_id"`
	TS         time.Time      `json:"ts"`
	Method     string         `json:"method"`
	URL        string         `json:"url"`
	Host       string         `json:"host"`
	Status     int            `json:"status"`
	Bytes      int64          `json:"bytes"`
	Verdict    string         `json:"verdict"`
	Reason     string         `json:"reason"`
	Purpose    string         `json:"purpose"`
	DurationMS int64          `json:"duration_ms"`
	Detail     map[string]any `json:"detail,omitempty"`
}

// Edge is one lineage link between two graph vertices.
type Edge struct {
	FromKind string `json:"from_kind"`
	FromID   int64  `json:"from_id"`
	ToKind   string `json:"to_kind"`
	ToID     int64  `json:"to_id"`
	Rel      string `json:"rel"`
}

// ---- observations: what a capability is allowed to return -------------------

// Observation is the ONLY way capability output enters the ledger.
//
// A capability cannot write arbitrary rows; it hands back normalised facts,
// candidate findings, and assets. The ledger assigns ids, dedupes, and links
// lineage - so a capability cannot claim a finding is verified, or invent a
// request_id that was never audited.
type Observation struct {
	Facts    []FactSeed    `json:"facts,omitempty"`
	Findings []FindingSeed `json:"findings,omitempty"`
	Assets   []AssetSeed   `json:"assets,omitempty"`
	// RequestIDs are the audit rows this observation rests on.
	RequestIDs []string `json:"request_ids,omitempty"`
	// Summary is a short, non-secret description for run records.
	Summary string `json:"summary,omitempty"`
}

// FactSeed is a fact before it has an id.
type FactSeed struct {
	Statement string         `json:"statement"`
	Evidence  map[string]any `json:"evidence,omitempty"`
	Tags      []string       `json:"tags,omitempty"`
	// Anchors are asset values ("host:x", "surface:https://x/y").
	Anchors []string `json:"anchors,omitempty"`
}

// FindingSeed is a finding before it has an id. There is no State field on
// purpose: everything a capability produces is a candidate.
type FindingSeed struct {
	Title    string         `json:"title"`
	Severity string         `json:"severity"`
	Kind     string         `json:"kind"`
	Where    string         `json:"where"`
	Detail   string         `json:"detail"`
	Evidence map[string]any `json:"evidence,omitempty"`
	Tags     []string       `json:"tags,omitempty"`
	Anchors  []string       `json:"anchors,omitempty"`
}

// AssetSeed is one asset vertex.
type AssetSeed struct {
	Kind  string         `json:"kind"`
	Value string         `json:"value"`
	Props map[string]any `json:"props,omitempty"`
}

// Add merges another observation into o.
func (o *Observation) Add(other Observation) {
	o.Facts = append(o.Facts, other.Facts...)
	o.Findings = append(o.Findings, other.Findings...)
	o.Assets = append(o.Assets, other.Assets...)
	o.RequestIDs = append(o.RequestIDs, other.RequestIDs...)
	if other.Summary != "" {
		if o.Summary == "" {
			o.Summary = other.Summary
		} else {
			o.Summary += "; " + other.Summary
		}
	}
}

// Empty reports whether the observation carries nothing.
func (o Observation) Empty() bool {
	return len(o.Facts) == 0 && len(o.Findings) == 0 && len(o.Assets) == 0
}

// ---- helper values ---------------------------------------------------------

// DedupeKey is the idempotency key for a fact: statement + request_id.
func DedupeKey(statement string, evidence map[string]any) string {
	reqID := ""
	if evidence != nil {
		if s, ok := evidence["request_id"].(string); ok {
			reqID = s
		}
	}
	return Hash(statement, reqID)
}

// Hash returns a stable sha256 hex of the parts.
func Hash(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0x1f})
		}
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalArgs renders intent args deterministically, for fingerprints and
// dedupe.
func CanonicalArgs(args map[string]any) string {
	if len(args) == 0 {
		return "{}"
	}
	// json.Marshal sorts map keys, which is exactly the determinism we need.
	b, err := json.Marshal(args)
	if err != nil {
		keys := make([]string, 0, len(args))
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&sb, "%s=%v;", k, args[k])
		}
		return sb.String()
	}
	return string(b)
}

// Fingerprint binds an intent to its exact capability and arguments. An approval
// names a fingerprint, so it can never authorise a different action.
func Fingerprint(engagementID int64, capability string, args map[string]any) string {
	return "sha256:" + Hash(
		"youkai-intent-v1",
		fmt.Sprintf("%d", engagementID),
		capability,
		CanonicalArgs(args),
	)
}

// NormaliseSeverity clamps unknown severities to "info".
func NormaliseSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}
