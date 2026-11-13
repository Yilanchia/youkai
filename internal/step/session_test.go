package step

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"youkai/internal/graph"
	"youkai/internal/mcp"
)

type fakeCall struct {
	Hand string
	Tool string
	Args map[string]any
}

type fakeHands struct {
	routes  map[string]string
	handler func(tool string, args map[string]any) (mcp.ToolResult, error)

	mu    sync.Mutex
	calls []fakeCall
}

func (f *fakeHands) HandFor(tool string) (string, error) {
	if h, ok := f.routes[tool]; ok {
		return h, nil
	}
	return "", fmt.Errorf("no hand owns %q", tool)
}

func (f *fakeHands) Call(_ context.Context, hand, tool string, args map[string]any) (mcp.ToolResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{Hand: hand, Tool: tool, Args: args})
	f.mu.Unlock()
	if f.handler == nil {
		return mcp.ToolResult{}, nil
	}
	return f.handler(tool, args)
}

func (f *fakeHands) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeHands) last() fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return fakeCall{}
	}
	return f.calls[len(f.calls)-1]
}

func okJSON(v any) mcp.ToolResult {
	b, _ := json.Marshal(v)
	return mcp.ToolResult{Content: []mcp.ToolContent{{Type: "text", Text: string(b)}}}
}

func openOwner(t *testing.T) *graph.Owner {
	t.Helper()
	o, err := graph.Open(filepath.Join(t.TempDir(), ".youkai", "explore.json"))
	if err != nil {
		t.Fatalf("open owner: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func paramHands() *fakeHands {
	return &fakeHands{
		routes: map[string]string{"web_param": "fairy", "web_compare": "fairy", "web_probe": "fairy"},
		handler: func(tool string, args map[string]any) (mcp.ToolResult, error) {
			return okJSON(map[string]any{
				"ok": true, "request_id": "req-step-1",
				"findings": []any{map[string]any{"kind": "ssti", "where": "http://lab.invalid/s?q=1"}},
			}), nil
		},
	}
}

func proposeParams(t *testing.T, s *Session) Proposal {
	t.Helper()
	p, err := s.Propose("web_param",
		map[string]any{"urls": []string{"http://lab.invalid/s?q=1"}, "param": "q"},
		"反射已观察到,确认是否可注入",
		"SSTI/SQLi 存在性命中",
		"首次命中即停")
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	return p
}

// TestExecuteRefusedWithoutApproval is the module-8 acceptance test's first half:
// a proposal alone executes nothing.
func TestExecuteRefusedWithoutApproval(t *testing.T) {
	fake := paramHands()
	s := New(openOwner(t), fake, "demo")
	p := proposeParams(t, s)

	if p.Tier != 2 {
		t.Fatalf("web_param classified tier %d, want 2", p.Tier)
	}
	if p.ExactRequest == "" || p.MinImpact == "" || p.StopCondition == "" || p.Rationale == "" {
		t.Fatalf("proposal is missing evidence fields: %+v", p)
	}
	if s.State() != StateAwaiting {
		t.Fatalf("state = %q, want awaiting_approval", s.State())
	}

	if _, err := s.Execute(context.Background()); err == nil {
		t.Fatal("Execute ran a tier-2 action with no operator approval")
	}
	if fake.count() != 0 {
		t.Fatalf("the hand was called %d time(s) without approval", fake.count())
	}
}

// TestApprovalIsBoundAndSingleUse covers reuse, batch pre-authorisation and
// "youkai self-signing".
func TestApprovalIsBoundAndSingleUse(t *testing.T) {
	fake := paramHands()
	s := New(openOwner(t), fake, "demo")
	p := proposeParams(t, s)

	// Not a confirmation.
	if err := s.Approve(Approval{Fingerprint: p.Fingerprint, Operator: "alice", Basis: "test"}); err == nil {
		t.Fatal("approval without confirm=true was accepted")
	}
	// No operator: an anonymous approval is not an approval.
	if err := s.Approve(Approval{Fingerprint: p.Fingerprint, Basis: "test", Confirm: true}); err == nil {
		t.Fatal("approval without an operator was accepted")
	}
	// Wrong binding.
	if err := s.Approve(Approval{Fingerprint: "sha256:deadbeef", Operator: "alice", Basis: "test", Confirm: true}); err == nil {
		t.Fatal("approval for a different proposal was accepted")
	}

	good := Approval{
		Fingerprint: p.Fingerprint, Operator: "alice", Basis: "authorised lab engagement",
		HighAuthPath: ".fairy/high-auth.json", Confirm: true,
	}
	if err := s.Approve(good); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// A second approval for the same step is refused (no stacking).
	if err := s.Approve(good); err == nil {
		t.Fatal("a second approval was stacked onto one proposal")
	}

	rec, err := s.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !rec.OK || rec.RequestID != "req-step-1" || rec.ApprovedBy != "alice" {
		t.Fatalf("record = %+v", rec)
	}
	if fake.count() != 1 {
		t.Fatalf("hand called %d times for one approved step", fake.count())
	}
	// The single confirm is passed to the hand.
	if v, ok := fake.last().Args["confirm"].(bool); !ok || !v {
		t.Fatal("confirm=true was not passed to the hand")
	}
	if s.State() != StateExecuted {
		t.Fatalf("state = %q, want executed", s.State())
	}

	// Executing the same step again is impossible.
	if _, err := s.Execute(context.Background()); err == nil {
		t.Fatal("a consumed step executed twice")
	}

	// Step 2 needs a brand-new approval; the old one must not carry over.
	p2 := proposeParams(t, s)
	if p2.Fingerprint == p.Fingerprint {
		t.Fatal("a new step reused the previous fingerprint")
	}
	if _, err := s.Execute(context.Background()); err == nil {
		t.Fatal("step 2 executed with no approval, reusing the previous authorisation")
	}
	if err := s.Approve(good); err == nil {
		t.Fatal("the previous approval was accepted for the next step")
	}
	if fake.count() != 1 {
		t.Fatalf("hand called %d times; only one approved step should have run", fake.count())
	}
}

// TestNoDoublePropose: one proposal on the table at a time, no batching.
func TestNoDoublePropose(t *testing.T) {
	s := New(openOwner(t), paramHands(), "demo")
	proposeParams(t, s)
	if _, err := s.Propose("web_compare", map[string]any{"url": "http://lab.invalid/x"},
		"r", "i", "s"); err == nil {
		t.Fatal("a second proposal was queued without resolving the first")
	}
}

// TestProposalMustBeReviewable.
func TestProposalMustBeReviewable(t *testing.T) {
	s := New(openOwner(t), paramHands(), "demo")
	if _, err := s.Propose("web_param", nil, "", "impact", "stop"); err == nil {
		t.Fatal("proposal with no rationale was accepted")
	}
	if _, err := s.Propose("web_param", nil, "why", "", "stop"); err == nil {
		t.Fatal("proposal with no expected impact was accepted")
	}
	if _, err := s.Propose("web_param", nil, "why", "impact", ""); err == nil {
		t.Fatal("proposal with no stop condition was accepted")
	}
	if s.State() != StateIdle {
		t.Fatalf("a rejected proposal changed state to %q", s.State())
	}
}

// TestTierThreeIsRefused even with a human at the keyboard.
func TestTierThreeIsRefused(t *testing.T) {
	s := New(openOwner(t), paramHands(), "demo")
	if _, err := s.Propose("exploit_getshell", map[string]any{"host": "lab.invalid"}, "r", "i", "s"); err == nil {
		t.Fatal("a tier-3 action was proposable")
	}
}

// TestProposeNextFromParkedIntent walks the step the loop stopped in front of.
func TestProposeNextFromParkedIntent(t *testing.T) {
	owner := openOwner(t)
	intent, err := owner.Apply(graph.CmdAddNode(graph.NodeSeed{
		Kind: graph.KindIntent,
		Props: map[string]any{
			"action": "web_param",
			"args":   map[string]any{"urls": []string{"http://lab.invalid/s?q=1"}, "param": "q"},
			"tier":   2,
			"status": graph.StatusNeedsApproval,
			"reason": "needs a human",
		},
		Anchors: []string{"host:lab.invalid"},
	}))
	if err != nil {
		t.Fatalf("seed intent: %v", err)
	}
	// A supporting fact, so the proposal has an evidence trail.
	if _, err := owner.Apply(graph.CmdAddFact(graph.FactSeed{
		Statement: "参数反射待浏览器复核:GET http://lab.invalid/s?q=1 (param: q)",
		Evidence:  map[string]any{"request_id": "req-scan-7"},
		Tags:      []string{"reflects"},
		Anchors:   []string{"host:lab.invalid"},
	})); err != nil {
		t.Fatalf("seed fact: %v", err)
	}

	fake := paramHands()
	s := New(owner, fake, "demo")

	p, err := s.ProposeNext()
	if err != nil {
		t.Fatalf("ProposeNext: %v", err)
	}
	if p.IntentID != intent.NodeID {
		t.Fatalf("proposal intent = %d, want %d", p.IntentID, intent.NodeID)
	}
	if len(p.Evidence) == 0 || !strings.Contains(p.Evidence[0], "req-scan-7") {
		t.Fatalf("proposal has no evidence trail: %v", p.Evidence)
	}

	if err := s.Approve(Approval{
		Fingerprint: p.Fingerprint, Operator: "alice", Basis: "lab scope, ticket 42", Confirm: true,
	}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := s.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	g := owner.Snapshot()
	n, _ := g.Node(intent.NodeID)
	if n.Status() != graph.StatusDone {
		t.Fatalf("intent status = %q, want done", n.Status())
	}
	if !strings.Contains(n.String("trace"), "alice") {
		t.Fatalf("intent trace does not name the approver: %q", n.String("trace"))
	}
	// Evidence written back with the request id, as a fact - not a verified claim.
	var found bool
	for _, f := range g.OfKind(graph.KindFact) {
		if strings.Contains(f.String("statement"), "人工放行执行 web_param") {
			found = true
			ev, _ := f.Prop("evidence").(map[string]any)
			if ev["request_id"] != "req-step-1" {
				t.Fatalf("step fact evidence = %v", ev)
			}
			if ev["operator"] != "alice" {
				t.Fatalf("step fact does not record the operator: %v", ev)
			}
		}
	}
	if !found {
		t.Fatal("the executed step left no evidence in the graph")
	}
}

// TestVerdictRequiresOperatorConfirm: candidate -> verified is a human act.
func TestVerdictRequiresOperatorConfirm(t *testing.T) {
	owner := openOwner(t)
	res, err := owner.Apply(graph.CmdAddNode(graph.NodeSeed{
		Kind:  graph.KindFinding,
		Props: map[string]any{"title": "reflection", "where": "x", "status": "candidate"},
	}))
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	s := New(owner, paramHands(), "demo")

	if err := s.Verdict(res.NodeID, false, "looks real"); err == nil {
		t.Fatal("an unconfirmed verdict was accepted")
	}
	if err := s.Verdict(res.NodeID, true, ""); err == nil {
		t.Fatal("a verified finding without an operator note was accepted")
	}
	if got := owner.Snapshot(); func() string { n, _ := got.Node(res.NodeID); return n.Status() }() != "candidate" {
		t.Fatal("the finding changed state without a valid verdict")
	}
	if err := s.Verdict(res.NodeID, true, "reproduced in a browser, context confirmed"); err != nil {
		t.Fatalf("Verdict: %v", err)
	}
	n, _ := owner.Snapshot().Node(res.NodeID)
	if n.Status() != "verified" {
		t.Fatalf("finding status = %q", n.Status())
	}
	if !strings.Contains(n.String("trace"), "operator verdict") {
		t.Fatalf("verdict was not recorded: %q", n.String("trace"))
	}
}

// TestStopEndsTheSession.
func TestStopEndsTheSession(t *testing.T) {
	s := New(openOwner(t), paramHands(), "demo")
	s.Stop("impact proven")
	if s.State() != StateStopped {
		t.Fatalf("state = %q", s.State())
	}
	if _, err := s.Propose("web_param", nil, "r", "i", "s"); err == nil {
		t.Fatal("a stopped session accepted a new proposal")
	}
}

// TestFingerprintChangesWithArgs: an approval for one URL cannot authorise otra.
func TestFingerprintChangesWithArgs(t *testing.T) {
	s := New(openOwner(t), paramHands(), "demo")
	p := proposeParams(t, s)
	other := p
	other.Args = map[string]any{"urls": []string{"http://lab.invalid/admin"}, "param": "q"}
	if Fingerprint(other, "nonce") == Fingerprint(p, "nonce") {
		t.Fatal("different args produced the same fingerprint")
	}
	if Fingerprint(p, "nonce-a") == Fingerprint(p, "nonce-b") {
		t.Fatal("fingerprints are not bound to the session nonce")
	}
}
