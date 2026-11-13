// Package step implements the human-controlled stepping mode (module 8).
//
// This is NOT part of the autonomous loop. The loop stops in front of every
// tier>=2 action and stays there. This package is what the operator enters when
// they decide to walk one exploitation step: youkai proposes EXACTLY ONE action,
// explains it, and refuses to execute it until a human hands back a fresh,
// single-use approval bound to that exact proposal.
//
// Structural guarantees, not conventions:
//   - one proposal on the table at a time; Propose refuses while one is pending
//   - an approval carries a fingerprint of the proposal it approves: a stale or
//     reused approval is rejected
//   - Execute consumes the approval BEFORE calling the hand, so a single approval
//     can never run twice, and no "batch pre-authorisation" is representable
//   - youkai never holds FAIRY_AUTH_KEY: the high-auth record and its signing key
//     stay with the human, and youkai only records the path for evidence
//   - candidate -> verified requires an explicit operator verdict
package step

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"youkai/internal/gate"
	"youkai/internal/graph"
	"youkai/internal/mcp"
	"youkai/internal/result"
	"youkai/internal/wording"
)

// Hands is the same shape the loop uses; hands.Set satisfies both.
type Hands interface {
	HandFor(tool string) (string, error)
	Call(ctx context.Context, hand, tool string, args map[string]any) (mcp.ToolResult, error)
}

// State is the session's position in the strict 1-6 cycle.
type State string

const (
	// StateIdle: nothing proposed; the operator may ask for one action.
	StateIdle State = "idle"
	// StateAwaiting: exactly one action is on the table, not executed.
	StateAwaiting State = "awaiting_approval"
	// StateExecuted: the approved action ran; awaiting the operator's verdict or
	// the next proposal.
	StateExecuted State = "executed"
	// StateStopped: the operator ended the chain.
	StateStopped State = "stopped"
)

// Proposal is one action the operator may approve. It is a description, never a
// side effect.
type Proposal struct {
	Index  int            `json:"index"`
	Action string         `json:"action"`
	Args   map[string]any `json:"args"`
	Tier   int            `json:"tier"`
	// Rationale is why this step, now.
	Rationale string `json:"rationale"`
	// ExpectedImpact is what the operator expects to prove.
	ExpectedImpact string `json:"expected_impact"`
	// StopCondition is when to stop, recorded before the action runs.
	StopCondition string `json:"stop_condition"`
	// ExactRequest is the literal request/text the hand will send.
	ExactRequest string `json:"exact_request"`
	// MinImpact is the smallest observable effect that counts as proof.
	MinImpact string `json:"min_impact"`
	// Evidence lists the facts (with request ids) this proposal rests on.
	Evidence []string `json:"evidence,omitempty"`
	// IntentID links back to the graph intent, when the proposal came from one.
	IntentID int64 `json:"intent_id,omitempty"`
	// Fingerprint is what an approval must name.
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

// Approval is the operator's authorisation for exactly one proposal.
type Approval struct {
	// Fingerprint must equal the pending proposal's fingerprint.
	Fingerprint string
	// Operator is the human who approved. Required: an anonymous approval is not
	// an approval.
	Operator string
	// Basis is why they approved (recorded as evidence).
	Basis string
	// HighAuthPath is the path to the Fairy high-auth record the operator created.
	// youkai records it; the signing key never leaves the human.
	HighAuthPath string
	// Confirm is the single-use confirmation flag; Execute consumes it.
	Confirm bool
}

// Record is one executed step, kept for the report and the graph.
type Record struct {
	Step          int       `json:"step"`
	Action        string    `json:"action"`
	Hand          string    `json:"hand"`
	ApprovedBy    string    `json:"approved_by"`
	ApprovalBasis string    `json:"approval_basis"`
	HighAuthPath  string    `json:"high_auth_path,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
	AuditPath     string    `json:"audit_path,omitempty"`
	RunID         string    `json:"run_id,omitempty"`
	OK            bool      `json:"ok"`
	Err           string    `json:"error,omitempty"`
	Summary       string    `json:"summary"`
	ExecutedAt    time.Time `json:"executed_at"`
}

// Session is one human-stepped chain.
type Session struct {
	mu sync.Mutex

	owner   *graph.Owner
	hands   Hands
	project string
	// nonce binds fingerprints to this session.
	nonce string

	state    State
	index    int
	proposal *Proposal
	approval *Approval
	records  []Record
	stopNote string
}

// New starts a session. owner may be nil for a dry rehearsal, in which case no
// graph evidence is written (the CLI always passes one).
func New(owner *graph.Owner, h Hands, project string) *Session {
	return &Session{
		owner:   owner,
		hands:   h,
		project: project,
		nonce:   fmt.Sprintf("%d", time.Now().UnixNano()),
		state:   StateIdle,
	}
}

// State returns the current state.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Proposal returns the pending proposal, if any.
func (s *Session) Proposal() (Proposal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proposal == nil {
		return Proposal{}, false
	}
	return *s.proposal, true
}

// Records returns the executed steps.
func (s *Session) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.records...)
}

// Fingerprint binds a proposal to a session and a step index. It is public
// because the operator needs it to authorise; the secret (the HMAC key) is not.
func Fingerprint(p Proposal, nonce string) string {
	args := canonicalJSON(p.Args)
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"youkai-step-v1", nonce, fmt.Sprintf("%d", p.Index), p.Action, args,
	}, "\x1f")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalJSON(v any) string {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	// json.Marshal already sorts map keys.
	return string(b)
}

// Propose puts exactly one action on the table. It never executes.
func (s *Session) Propose(action string, args map[string]any, rationale, expectedImpact, stopCondition string) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StateStopped {
		return Proposal{}, fmt.Errorf("session stopped: %s", s.stopNote)
	}
	if s.state == StateAwaiting {
		return Proposal{}, fmt.Errorf("a proposal is already on the table (step %d); execute or withdraw it before proposing another", s.proposal.Index)
	}
	if strings.TrimSpace(action) == "" {
		return Proposal{}, fmt.Errorf("propose: empty action")
	}
	if args == nil {
		args = map[string]any{}
	}

	dec := gate.Explain(action, args)
	if dec.Tier == gate.TierDeep {
		// Deep exploitation does not exist in this build, human or not.
		return Proposal{}, fmt.Errorf("refused: %s is tier3 (%s); this build has no exploitation path", action, dec.Reason)
	}

	s.index++
	p := Proposal{
		Index:          s.index,
		Action:         action,
		Args:           args,
		Tier:           int(dec.Tier),
		Rationale:      rationale,
		ExpectedImpact: expectedImpact,
		StopCondition:  stopCondition,
		ExactRequest:   wording.Describe(action, args),
		MinImpact:      wording.MinImpact(action),
		CreatedAt:      time.Now().UTC(),
	}
	p.Fingerprint = Fingerprint(p, s.nonce)

	if p.Rationale == "" {
		return Proposal{}, fmt.Errorf("propose: a proposal without a rationale is not reviewable")
	}
	if p.ExpectedImpact == "" {
		return Proposal{}, fmt.Errorf("propose: a proposal without expected impact is not reviewable")
	}
	if p.StopCondition == "" {
		return Proposal{}, fmt.Errorf("propose: a proposal without a stop condition is not reviewable")
	}

	// Attach the evidence trail: related facts with their request ids.
	if s.owner != nil {
		p.Evidence = relatedEvidence(s.owner.Snapshot(), args)
	}

	s.proposal = &p
	s.approval = nil
	s.state = StateAwaiting
	return p, nil
}

// ProposeNext proposes the graph's next parked tier>=2 intent - the door the
// autonomous loop stopped at - as a single step.
func (s *Session) ProposeNext() (Proposal, error) {
	s.mu.Lock()
	if s.owner == nil {
		s.mu.Unlock()
		return Proposal{}, fmt.Errorf("no graph attached")
	}
	s.mu.Unlock()

	g := s.owner.Snapshot()
	intents := g.OfKind(graph.KindIntent)
	sort.Slice(intents, func(i, j int) bool { return intents[i].ID < intents[j].ID })
	for _, n := range intents {
		if n.Status() != graph.StatusNeedsApproval {
			continue
		}
		args := n.Map("args")
		rationale := n.String("rationale")
		if rationale == "" {
			rationale = "the loop parked this step at needs_approval"
		}
		expected := n.String("expected_fact")
		if expected == "" {
			// A parked intent always has an expected effect: the minimum proof.
			expected = "证明该步的最小影响成立:" + wording.MinImpact(n.String("action"))
		}
		p, err := s.Propose(n.String("action"), args, rationale,
			expected, wording.StopCondition(n.String("action")))
		if err != nil {
			return Proposal{}, err
		}
		s.mu.Lock()
		s.proposal.IntentID = n.ID
		p.IntentID = n.ID
		s.mu.Unlock()
		return p, nil
	}
	return Proposal{}, fmt.Errorf("no intent is parked at needs_approval")
}

// Approve records the operator's authorisation for the pending proposal.
//
// It refuses anything that is not a fresh, explicit, correctly-bound approval.
func (s *Session) Approve(a Approval) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateAwaiting || s.proposal == nil {
		return fmt.Errorf("nothing to approve: state is %s", s.state)
	}
	if !a.Confirm {
		return fmt.Errorf("approval refused: confirm must be true (a single explicit confirmation per step)")
	}
	if strings.TrimSpace(a.Operator) == "" {
		return fmt.Errorf("approval refused: operator is required")
	}
	if strings.TrimSpace(a.Basis) == "" {
		return fmt.Errorf("approval refused: basis is required (why is this step authorised?)")
	}
	if a.Fingerprint != s.proposal.Fingerprint {
		return fmt.Errorf("approval refused: fingerprint %q does not name the pending proposal %s (stale or reused approval)",
			a.Fingerprint, s.proposal.Fingerprint)
	}
	if s.approval != nil {
		return fmt.Errorf("approval refused: this proposal already has an approval; one per step")
	}
	cp := a
	s.approval = &cp
	return nil
}

// Execute runs the one approved action.
//
// Order is deliberate: validate, consume the approval, then call. A call that
// fails still consumed the approval - re-running requires a new human decision.
func (s *Session) Execute(ctx context.Context) (Record, error) {
	s.mu.Lock()
	if s.state != StateAwaiting || s.proposal == nil {
		s.mu.Unlock()
		return Record{}, fmt.Errorf("nothing to execute: state is %s", s.state)
	}
	if s.approval == nil {
		s.mu.Unlock()
		return Record{}, fmt.Errorf("execute refused: no operator approval for step %d (youkai cannot self-approve)", s.proposal.Index)
	}
	p := *s.proposal
	a := *s.approval
	// Consume before the call: a single approval cannot run twice, and a failure
	// does not leave a usable approval behind.
	s.approval = nil
	s.mu.Unlock()

	rec := Record{
		Step:          p.Index,
		Action:        p.Action,
		ApprovedBy:    a.Operator,
		ApprovalBasis: a.Basis,
		HighAuthPath:  a.HighAuthPath,
		ExecutedAt:    time.Now().UTC(),
	}

	dec := gate.Explain(p.Action, p.Args)
	if dec.Tier == gate.TierDeep {
		s.finish(&rec, false, "refused at execution: tier3")
		return rec, fmt.Errorf("refused: tier3 action")
	}

	hand, err := s.hands.HandFor(p.Action)
	if err != nil {
		s.finish(&rec, false, "no hand owns this tool: "+err.Error())
		return rec, err
	}
	rec.Hand = hand

	args := make(map[string]any, len(p.Args)+2)
	for k, v := range p.Args {
		args[k] = v
	}
	// The single confirm the design requires, and the project Fairy needs.
	args["confirm"] = true
	if hand == "fairy" && s.project != "" {
		if _, ok := args["project"]; !ok {
			args["project"] = s.project
		}
	}

	res, err := s.hands.Call(ctx, hand, p.Action, args)
	if err != nil {
		s.finish(&rec, false, "hand call failed: "+err.Error())
		return rec, err
	}
	if res.IsError {
		msg := "hand refused: " + firstLine(res.Text())
		s.finish(&rec, false, msg)
		return rec, fmt.Errorf("%s", msg)
	}

	rec.RequestID = result.RequestID(res.Text())
	rec.AuditPath = result.AuditPath(res.Text())
	rec.RunID = result.RunID(res.Text())
	rec.OK = true
	rec.Summary = fmt.Sprintf("%s via %s ok, request_id=%s audit=%s", p.Action, hand, orNone(rec.RequestID), orNone(rec.AuditPath))
	s.finish(&rec, true, "")

	s.writeEvidence(p, a, rec)
	return rec, nil
}

// finish closes out a record under the lock.
func (s *Session) finish(rec *Record, ok bool, errMsg string) {
	rec.OK = ok
	rec.Err = errMsg
	if rec.Summary == "" {
		rec.Summary = errMsg
	}
	s.mu.Lock()
	s.records = append(s.records, *rec)
	if ok {
		s.state = StateExecuted
	} else {
		// A failed step also leaves the operator in the "nothing pending" state,
		// but the step counter already advanced: no silent retry.
		s.state = StateExecuted
	}
	s.proposal = nil
	s.mu.Unlock()
}

// writeEvidence puts the execution into the graph: a fact with the request id,
// a trace on the intent, and the intent marked done. Never a verified claim.
func (s *Session) writeEvidence(p Proposal, a Approval, rec Record) {
	if s.owner == nil {
		return
	}
	evidence := map[string]any{
		"request_id": rec.RequestID,
		"audit_path": rec.AuditPath,
		"run_id":     rec.RunID,
		"operator":   a.Operator,
		"basis":      a.Basis,
		"high_auth":  a.HighAuthPath,
		"tier":       p.Tier,
		"step":       p.Index,
	}
	_ = s.owner
	res, err := s.owner.Apply(graph.CmdAddFact(graph.FactSeed{
		Statement: fmt.Sprintf("人工放行执行 %s:%s", p.Action, p.ExactRequest),
		Evidence:  evidence,
		Tags:      []string{"step", "human-approved", p.Action},
	}))
	if err != nil {
		return
	}
	if p.IntentID != 0 {
		_, _ = s.owner.Apply(graph.CmdAddEdge(res.NodeID, p.IntentID, graph.RelSupports))
		_, _ = s.owner.Apply(graph.CmdAddTrace(p.IntentID, fmt.Sprintf(
			"human step %d executed by %s (basis: %s)", p.Index, a.Operator, a.Basis)))
		_, _ = s.owner.Apply(graph.CmdSetStatus(p.IntentID, graph.StatusDone))
	}
}

// Verdict applies the operator's judgement to a finding.
//
// candidate -> verified ONLY when the operator explicitly confirmed it. There is
// no other code path that writes "verified".
func (s *Session) Verdict(findingID int64, confirmed bool, note string) error {
	if s.owner == nil {
		return fmt.Errorf("no graph attached")
	}
	if !confirmed {
		return fmt.Errorf("verdict refused: candidate stays candidate until the operator confirms it explicitly")
	}
	if strings.TrimSpace(note) == "" {
		return fmt.Errorf("verdict refused: a verified finding needs the operator's note")
	}
	g := s.owner.Snapshot()
	n, ok := g.Node(findingID)
	if !ok {
		return fmt.Errorf("verdict: unknown node %d", findingID)
	}
	if n.Kind != graph.KindFinding {
		return fmt.Errorf("verdict: node %d is a %s, not a finding", findingID, n.Kind)
	}
	if _, err := s.owner.Apply(graph.CmdSetStatus(findingID, "verified")); err != nil {
		return err
	}
	_, err := s.owner.Apply(graph.CmdAddTrace(findingID, "operator verdict: verified - "+note))
	return err
}

// Stop ends the session. The chain does not continue.
func (s *Session) Stop(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StateStopped
	s.stopNote = reason
	s.approval = nil
}

// ---- helpers ---------------------------------------------------------------

func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 240 {
		return s[:240] + "…"
	}
	return s
}

func relatedEvidence(g *graph.Graph, args map[string]any) []string {
	if g == nil {
		return nil
	}
	var out []string
	anchors := map[string]bool{}
	for _, u := range collectURLs(args) {
		if h := hostOfURL(u); h != "" {
			anchors["host:"+h] = true
		}
	}
	for _, f := range g.OfKind(graph.KindFact) {
		for _, a := range g.Anchors(f.ID) {
			if anchors[a] {
				ev := ""
				if m, ok := f.Prop("evidence").(map[string]any); ok {
					if id, ok := m["request_id"].(string); ok {
						ev = " request_id=" + id
					}
				}
				out = append(out, fmt.Sprintf("#%d %s%s", f.ID, f.String("statement"), ev))
				break
			}
		}
	}
	return out
}

func collectURLs(args map[string]any) []string {
	var out []string
	if s, ok := args["url"].(string); ok {
		out = append(out, s)
	}
	switch v := args["urls"].(type) {
	case []string:
		out = append(out, v...)
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func hostOfURL(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
