package loop

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

// ---- fakes -----------------------------------------------------------------

type fakeCall struct {
	Hand string
	Tool string
	Args map[string]any
}

type fakeHands struct {
	routes  map[string]string // tool -> hand
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
		return mcp.ToolResult{}, fmt.Errorf("no handler for %q", tool)
	}
	return f.handler(tool, args)
}

// IngestIntoFairy makes fakeHands a ledgerSink, so the Verdex -> Fairy mirror is
// exercised instead of silently skipped.
func (f *fakeHands) IngestIntoFairy(ctx context.Context, project, source string, payload any) (bool, string) {
	_, err := f.Call(ctx, "fairy", "fairy_ingest", map[string]any{
		"project": project, "source": source, "payload": payload,
	})
	if err != nil {
		return false, err.Error()
	}
	return true, "ingested"
}

func (f *fakeHands) called(tool string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.Tool == tool {
			n++
		}
	}
	return n
}

func (f *fakeHands) tools() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.Tool)
	}
	return out
}

func okJSON(v any) mcp.ToolResult {
	b, _ := json.Marshal(v)
	return mcp.ToolResult{Content: []mcp.ToolContent{{Type: "text", Text: string(b)}}}
}

func toolErr(msg string) mcp.ToolResult {
	return mcp.ToolResult{IsError: true, Content: []mcp.ToolContent{{Type: "text", Text: msg}}}
}

// ---- helpers ---------------------------------------------------------------

func openOwner(t *testing.T) *graph.Owner {
	t.Helper()
	o, err := graph.Open(filepath.Join(t.TempDir(), ".youkai", "explore.json"))
	if err != nil {
		t.Fatalf("open owner: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func mustApply(t *testing.T, o *graph.Owner, cmd graph.Command) graph.ApplyResult {
	t.Helper()
	res, err := o.Apply(cmd)
	if err != nil {
		t.Fatalf("apply %s: %v", cmd.Op, err)
	}
	return res
}

func intentByAction(t *testing.T, g *graph.Graph, action string) *graph.Node {
	t.Helper()
	for _, n := range g.OfKind(graph.KindIntent) {
		if n.String("action") == action {
			return n
		}
	}
	return nil
}

func factStatements(g *graph.Graph) []string {
	var out []string
	for _, n := range g.OfKind(graph.KindFact) {
		out = append(out, n.String("statement"))
	}
	return out
}

func hasStatement(g *graph.Graph, substr string) bool {
	for _, s := range factStatements(g) {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// scanWithReflection is the fake web_scan payload: one reflection candidate with
// the exact "where" shape Fairy emits.
func scanWithReflection() mcp.ToolResult {
	return okJSON(map[string]any{
		"ok":         true,
		"run_id":     "run-1",
		"audit_path": ".fairy/audit/run-1.jsonl",
		"findings": []any{
			map[string]any{
				"id":       "F-001",
				"kind":     "reflection",
				"severity": "medium",
				"title":    "参数 q 的值反射进响应",
				"where":    "GET http://lab.invalid/search?q=1 (param: q)",
				"detail":   "标记原样出现在响应。",
				"evidence": map[string]any{"request_id": "req-scan-7", "status": 200},
			},
		},
		"attack_surface": map[string]any{"artifacts": []any{}},
	})
}

func probeOK(reqID string) mcp.ToolResult {
	return okJSON(map[string]any{
		"ok":         true,
		"request_id": reqID,
		"url":        "http://lab.invalid/.git/config",
		"status":     200,
		"body_bytes": 120,
		"audit_path": ".fairy/audit/run-1.jsonl",
	})
}

// ---- the acceptance tests --------------------------------------------------

// TestReadOnlyChainThenStopAtTierTwo is the module-3 acceptance test:
// no context is fed in, the loop derives the chain, runs the read-only steps,
// writes facts back, and stops in front of the tier-2 step - without ever
// approving or executing it.
func TestReadOnlyChainThenStopAtTierTwo(t *testing.T) {
	owner := openOwner(t)
	fake := &fakeHands{
		routes: map[string]string{
			"fairy_ledger_show":    "fairy",
			"web_probe":            "fairy",
			"web_scan":             "fairy",
			"web_param":            "fairy",
			"fairy_ledger_advance": "fairy",
		},
		handler: func(tool string, args map[string]any) (mcp.ToolResult, error) {
			switch tool {
			case "fairy_ledger_show":
				return okJSON(map[string]any{"assets": []any{}}), nil
			case "web_probe":
				return probeOK("req-probe-1"), nil
			case "web_scan":
				return scanWithReflection(), nil
			}
			return mcp.ToolResult{}, fmt.Errorf("unexpected tool %q", tool)
		},
	}

	r, err := New(Config{Project: "demo", SeedHosts: []string{"http://lab.invalid"}, MaxSteps: 6}, owner, fake)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if rep.Stop != StopNeedsApproval {
		t.Fatalf("stop = %q (%s), want %q", rep.Stop, rep.Reason, StopNeedsApproval)
	}
	if len(rep.Steps) != 2 {
		t.Fatalf("executed %d steps (%v), want the 2 read-only ones", len(rep.Steps), fake.tools())
	}
	for _, s := range rep.Steps {
		if !s.OK {
			t.Fatalf("step %s failed: %s", s.Action, s.Err)
		}
		if s.Tier != 1 {
			t.Fatalf("autonomous step %s ran at tier %d", s.Action, s.Tier)
		}
	}

	// Never executed, never approved.
	if n := fake.called("web_param"); n != 0 {
		t.Fatalf("tier-2 web_param was executed %d time(s) by the loop", n)
	}
	if n := fake.called("fairy_ledger_advance"); n != 0 {
		t.Fatalf("the loop tried to approve %d time(s)", n)
	}

	// Facts came back into the graph, with evidence.
	g := owner.Snapshot()
	if !hasStatement(g, "git 配置可读") {
		t.Fatalf("git fact missing; facts=%v", factStatements(g))
	}
	for _, f := range g.OfKind(graph.KindFact) {
		ev, _ := f.Prop("evidence").(map[string]any)
		if ev == nil || ev["request_id"] == nil {
			t.Fatalf("fact %q has no request_id evidence", f.String("statement"))
		}
	}

	// The tier-2 intent exists, is parked, and is explained to the human.
	param := intentByAction(t, g, "web_param")
	if param == nil {
		t.Fatal("the loop did not derive the tier-2 follow-up intent")
	}
	if param.Status() != graph.StatusNeedsApproval {
		t.Fatalf("tier-2 intent status = %q, want needs_approval", param.Status())
	}
	if param.Int("tier") != 2 {
		t.Fatalf("tier-2 intent carries tier %d", param.Int("tier"))
	}
	if len(rep.Pending) == 0 {
		t.Fatal("no pending hand-off was produced")
	}
	p := rep.Pending[0]
	if p.Action != "web_param" {
		t.Fatalf("pending action = %q", p.Action)
	}
	if !strings.Contains(p.ExactRequest, `param="q"`) {
		t.Fatalf("pending exact_request = %q", p.ExactRequest)
	}
	if p.MinImpact == "" || p.StopCondition == "" || p.HowToApprove == "" {
		t.Fatalf("pending hand-off is missing the four evidence fields: %+v", p)
	}
	if rep.ExploitProvider == "" {
		t.Fatal("report does not state the exploit provider's status")
	}
}

// TestTierTwoNeverRunsEvenWhenApproved is the module-5 acceptance test: an
// approved=true boolean in the file is not a human authorisation.
func TestTierTwoNeverRunsEvenWhenApproved(t *testing.T) {
	owner := openOwner(t)
	fake := &fakeHands{
		routes: map[string]string{
			"web_probe": "fairy",
			"web_scan":  "fairy",
			"assets":    "verdex",
			"web_param": "fairy",
		},
		handler: func(tool string, args map[string]any) (mcp.ToolResult, error) {
			switch tool {
			case "web_scan":
				return okJSON(map[string]any{"ok": true, "findings": []any{}}), nil
			case "web_probe":
				return probeOK("req-probe-9"), nil
			case "assets":
				return okJSON(map[string]any{"kind": "elf", "findings": []any{}}), nil
			}
			return mcp.ToolResult{}, fmt.Errorf("unexpected tool %q", tool)
		},
	}

	// A pre-seeded goal and a human-looking approval on a tier-2 intent.
	mustApply(t, owner, graph.CmdAddNode(graph.NodeSeed{
		Kind:  graph.KindGoal,
		Props: map[string]any{"statement": "只读取证:demo"},
	}))
	tier1 := mustApply(t, owner, graph.CmdAddNode(graph.NodeSeed{
		Kind: graph.KindIntent,
		Props: map[string]any{
			"action": "assets", "args": map[string]any{"path": "sample.bin"}, "tier": 1,
		},
	}))
	tier2 := mustApply(t, owner, graph.CmdAddNode(graph.NodeSeed{
		Kind: graph.KindIntent,
		Props: map[string]any{
			"action": "web_param",
			"args":   map[string]any{"urls": []string{"http://lab.invalid/x"}, "param": "q"},
			"tier":   2,
			// The dangerous case: someone (or a bug) wrote approved=true.
			"approved": true,
		},
	}))
	mustApply(t, owner, graph.CmdSetApproved(tier2.NodeID, true))

	r, err := New(Config{Project: "demo", MaxSteps: 5}, owner, fake)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if rep.Stop != StopNeedsApproval {
		t.Fatalf("stop = %q (%s), want needs_approval", rep.Stop, rep.Reason)
	}
	if n := fake.called("web_param"); n != 0 {
		t.Fatalf("approved=true unlocked tier2: web_param executed %d time(s)", n)
	}
	g := owner.Snapshot()
	two, _ := g.Node(tier2.NodeID)
	if two.Status() != graph.StatusNeedsApproval {
		t.Fatalf("tier2 intent status = %q", two.Status())
	}
	one, _ := g.Node(tier1.NodeID)
	if one.Status() != graph.StatusDone {
		t.Fatalf("tier1 intent should have run: status = %q (%s)", one.Status(), one.String("trace"))
	}
}

// TestFailureIsNotRetried: a hand failure leaves the intent active and the loop
// moves on. No retry, no crash.
func TestFailureIsNotRetried(t *testing.T) {
	owner := openOwner(t)
	fake := &fakeHands{
		routes: map[string]string{"web_probe": "fairy", "web_scan": "fairy"},
		handler: func(tool string, args map[string]any) (mcp.ToolResult, error) {
			if tool == "web_probe" {
				return mcp.ToolResult{}, fmt.Errorf("connection refused")
			}
			return okJSON(map[string]any{"ok": true, "findings": []any{}}), nil
		},
	}
	r, _ := New(Config{Project: "demo", SeedHosts: []string{"http://lab.invalid"}, MaxSteps: 6}, owner, fake)
	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run must not fail on a worker error: %v", err)
	}
	if n := fake.called("web_probe"); n != 1 {
		t.Fatalf("web_probe was retried: %d calls", n)
	}
	probe := intentByAction(t, owner.Snapshot(), "web_probe")
	if probe.Status() != graph.StatusActive {
		t.Fatalf("failed intent status = %q, want active (never retried)", probe.Status())
	}
	var sawErr bool
	for _, s := range rep.Steps {
		if s.Action == "web_probe" && s.Err != "" {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatal("the failed step was not reported")
	}
	if rep.Stop != StopIdle {
		t.Fatalf("stop = %q, want idle after the remaining work finished", rep.Stop)
	}
}

// TestSensitiveHitStopsTheRound: the loop stops the whole round, not just the
// step.
func TestSensitiveHitStopsTheRound(t *testing.T) {
	owner := openOwner(t)
	fake := &fakeHands{
		routes: map[string]string{"web_probe": "fairy", "web_scan": "fairy"},
		handler: func(tool string, args map[string]any) (mcp.ToolResult, error) {
			if tool == "web_probe" {
				return okJSON(map[string]any{
					"ok": true, "request_id": "req-1", "url": "http://lab.invalid/.git/config",
					"status": 200,
					// A leaked key in the body must stop everything.
					"body_snippet": "[core]\n\tkey = -----BEGIN RSA PRIVATE KEY-----\n",
				}), nil
			}
			return okJSON(map[string]any{"ok": true, "findings": []any{}}), nil
		},
	}
	r, _ := New(Config{Project: "demo", SeedHosts: []string{"http://lab.invalid"}, MaxSteps: 6}, owner, fake)
	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Stop != StopSensitive {
		t.Fatalf("stop = %q (%s), want sensitive_stop", rep.Stop, rep.Reason)
	}
	if rep.Sensitive == nil || rep.Sensitive.Name != "private-key" {
		t.Fatalf("sensitive hit not reported correctly: %+v", rep.Sensitive)
	}
	// The secret itself must not be copied into the record.
	if strings.Contains(rep.Reason, "PRIVATE KEY") {
		t.Fatalf("the report echoed the secret: %q", rep.Reason)
	}
	// The rest of the batch must not continue into another round.
	if n := fake.called("web_scan"); n != 1 {
		t.Fatalf("round continued after a sensitive hit: web_scan called %d", n)
	}
}

// TestIdleWithoutContext: no ledger, no seed hosts, no intents -> idle, no panic.
func TestIdleWithoutContext(t *testing.T) {
	owner := openOwner(t)
	fake := &fakeHands{routes: map[string]string{}}
	r, _ := New(Config{Project: "demo", MaxSteps: 4}, owner, fake)
	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Stop != StopIdle {
		t.Fatalf("stop = %q (%s), want idle", rep.Stop, rep.Reason)
	}
	if len(rep.Steps) != 0 {
		t.Fatalf("executed %d steps with no context", len(rep.Steps))
	}
}

// TestSecondRunDoesNotDuplicate: rules and facts are idempotent across runs.
func TestSecondRunDoesNotDuplicate(t *testing.T) {
	owner := openOwner(t)
	fake := &fakeHands{
		routes: map[string]string{"web_probe": "fairy", "web_scan": "fairy"},
		handler: func(tool string, args map[string]any) (mcp.ToolResult, error) {
			if tool == "web_probe" {
				return probeOK("req-probe-1"), nil
			}
			return okJSON(map[string]any{"ok": true, "findings": []any{}}), nil
		},
	}
	cfg := Config{Project: "demo", SeedHosts: []string{"http://lab.invalid"}, MaxSteps: 6}

	r1, _ := New(cfg, owner, fake)
	if _, err := r1.Run(context.Background()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	first := owner.Snapshot()
	factsBefore := len(first.OfKind(graph.KindFact))
	intentsBefore := len(first.OfKind(graph.KindIntent))

	r2, _ := New(cfg, owner, fake)
	rep, err := r2.Run(context.Background())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if rep.Stop != StopIdle {
		t.Fatalf("second run stop = %q, want idle", rep.Stop)
	}
	if len(rep.Steps) != 0 {
		t.Fatalf("second run re-executed %d intents", len(rep.Steps))
	}
	second := owner.Snapshot()
	if got := len(second.OfKind(graph.KindFact)); got != factsBefore {
		t.Fatalf("facts duplicated: %d -> %d", factsBefore, got)
	}
	if got := len(second.OfKind(graph.KindIntent)); got != intentsBefore {
		t.Fatalf("intents duplicated: %d -> %d", intentsBefore, got)
	}
}

// TestMaxStepsIsHonoured.
func TestMaxStepsIsHonoured(t *testing.T) {
	owner := openOwner(t)
	fake := &fakeHands{
		routes: map[string]string{"web_probe": "fairy", "web_scan": "fairy"},
		handler: func(tool string, args map[string]any) (mcp.ToolResult, error) {
			if tool == "web_probe" {
				return probeOK("req"), nil
			}
			return okJSON(map[string]any{"ok": true, "findings": []any{}}), nil
		},
	}
	r, _ := New(Config{Project: "demo", SeedHosts: []string{"http://lab.invalid"}, MaxSteps: 1, Concurrency: 1}, owner, fake)
	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Stop != StopMaxSteps {
		t.Fatalf("stop = %q, want max_steps", rep.Stop)
	}
	if len(rep.Steps) != 1 {
		t.Fatalf("executed %d steps with max_steps=1", len(rep.Steps))
	}
}

// TestProposalsNeedAnArchive: an LLM proposal without a replayable archive is
// discarded, and even a good one cannot escape the gate.
func TestProposalsNeedAnArchive(t *testing.T) {
	owner := openOwner(t)
	fake := &fakeHands{routes: map[string]string{"web_param": "fairy"}}
	mustApply(t, owner, graph.CmdAddNode(graph.NodeSeed{
		Kind:  graph.KindGoal,
		Props: map[string]any{"statement": "只读取证:demo"},
	}))

	r, _ := New(Config{
		Project:  "demo",
		MaxSteps: 4,
		Proposer: stubProposer{specs: []IntentSpec{
			{Action: "web_param", Args: map[string]any{"urls": []string{"http://lab.invalid/x"}, "param": "q"}},
			{Action: "web_scan", Args: map[string]any{"urls": []string{"http://lab.invalid"}}, Provenance: ".youkai/planner/1.json"},
		}},
	}, owner, fake)

	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	g := owner.Snapshot()
	if intentByAction(t, g, "web_param") != nil {
		t.Fatal("a proposal with no archive was written to the graph")
	}
	scan := intentByAction(t, g, "web_scan")
	if scan == nil {
		t.Fatal("a proposal with an archive was not accepted")
	}
	if !scan.Bool("inferred") {
		t.Fatal("LLM intent is not marked inferred")
	}
	if scan.String("provenance") != ".youkai/planner/1.json" {
		t.Fatalf("provenance not recorded: %q", scan.String("provenance"))
	}
	// The archived proposal is tier 1, so it would execute; the hand has no
	// handler, so it fails and stays active - the point is the gate, not success.
	if rep.Stop == StopNeedsApproval {
		t.Fatal("a tier-1 proposal was parked as if it were tier 2")
	}
}

type stubProposer struct{ specs []IntentSpec }

func (s stubProposer) Propose(context.Context, ProposeRequest) ([]IntentSpec, error) {
	return s.specs, nil
}

// ---- normaliser unit tests -------------------------------------------------

func TestProbeFactsMatchFairyWorkerSemantics(t *testing.T) {
	res := probeOK("req-1")
	obs := normalize("web_probe", map[string]any{"url": "http://lab.invalid/.git/config"}, res)
	if len(obs.Facts) != 2 {
		t.Fatalf("expected a status fact and a git fact, got %d: %v", len(obs.Facts), obs.Facts)
	}
	if obs.Facts[0].Statement != "GET http://lab.invalid/.git/config -> 200" {
		t.Fatalf("status fact = %q", obs.Facts[0].Statement)
	}
	if obs.Facts[1].Tags[0] != "git" {
		t.Fatalf("git fact tags = %v", obs.Facts[1].Tags)
	}
	if obs.Facts[1].Evidence["request_id"] != "req-1" {
		t.Fatalf("evidence lost request_id: %v", obs.Facts[1].Evidence)
	}

	// A 404 on .git/config must not produce an "exposed" fact.
	notFound := okJSON(map[string]any{"url": "http://lab.invalid/.git/config", "status": 404, "request_id": "r2"})
	obs = normalize("web_probe", nil, notFound)
	for _, f := range obs.Facts {
		if len(f.Tags) > 1 && f.Tags[0] == "git" {
			t.Fatal("404 produced a git-exposed fact")
		}
	}
}

func TestCompareFacts(t *testing.T) {
	res := okJSON(map[string]any{
		"url":     "http://lab.invalid/api/orders/1",
		"verdict": "marker-in-both",
		"a":       map[string]any{"request_id": "ra"},
		"b":       map[string]any{"request_id": "rb"},
	})
	obs := normalize("web_compare", nil, res)
	var found bool
	for _, f := range obs.Facts {
		if len(f.Tags) > 0 && f.Tags[0] == "bola" {
			found = true
			if f.Evidence["request_id_a"] != "ra" || f.Evidence["request_id_b"] != "rb" {
				t.Fatalf("compare evidence incomplete: %v", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("marker-in-both did not produce a BOLA candidate fact: %v", obs.Facts)
	}
}

func TestSensitiveScan(t *testing.T) {
	cases := []struct {
		text string
		want bool
		name string
	}{
		{"nothing here", false, ""},
		{"-----BEGIN OPENSSH PRIVATE KEY-----", true, "private-key"},
		{"aws AKIAIOSFODNN7EXAMPLE here", true, "aws-access-key"},
		{"token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig", true, "jwt"},
		{`password: "hunter2hunter2"`, true, "password-literal"},
		{`"sensitive_hit":true`, true, "hand-flagged"},
	}
	for _, c := range cases {
		hit, ok := ScanSensitive(c.text)
		if ok != c.want {
			t.Fatalf("ScanSensitive(%q) = %v, want %v", c.text, ok, c.want)
		}
		if ok && hit.Name != c.name {
			t.Fatalf("ScanSensitive(%q) name = %q, want %q", c.text, hit.Name, c.name)
		}
	}
}

func TestParamFollowUpTargetParsing(t *testing.T) {
	gotURL, gotParam, ok := paramFollowUpTarget(Fact{
		Statement: "参数反射待浏览器复核:GET https://lab.invalid/s?q=1 (param: q)",
	})
	if !ok {
		t.Fatal("could not parse a Fairy reflection location")
	}
	if gotURL != "https://lab.invalid/s?q=1" || gotParam != "q" {
		t.Fatalf("parsed %q / %q", gotURL, gotParam)
	}

	// Unparseable input must not invent a target.
	if _, _, ok := paramFollowUpTarget(Fact{Statement: "no location here"}); ok {
		t.Fatal("invented a target from a bare statement")
	}
}

func TestHostsFromLedger(t *testing.T) {
	text := `{"assets":[{"value":"https://lab.invalid/a"},{"host":"api.lab.invalid"}]}`
	got := hostsFromLedger(text)
	if len(got) != 2 {
		t.Fatalf("hosts = %v", got)
	}
	if got[0] != "https://lab.invalid" && got[0] != "http://api.lab.invalid" {
		t.Fatalf("unexpected normalisation: %v", got)
	}
	for _, h := range got {
		if strings.HasSuffix(h, "/a") {
			t.Fatalf("path not stripped: %v", got)
		}
	}
}

// TestVerdexHandoffAndReadOnlyAnalysis is the module-6 acceptance test: a sample
// that Fairy noticed is registered without being downloaded, a local sample is
// analysed read-only, and the file:line findings land in the same graph as
// candidates - with the raw result mirrored into Fairy's ledger.
func TestVerdexHandoffAndReadOnlyAnalysis(t *testing.T) {
	owner := openOwner(t)
	var handoffArgs []map[string]any

	fake := &fakeHands{
		routes: map[string]string{
			"fairy_handoff":  "fairy",
			"fairy_ingest":   "fairy",
			"analyze_target": "verdex",
		},
		handler: func(tool string, args map[string]any) (mcp.ToolResult, error) {
			switch tool {
			case "fairy_handoff":
				handoffArgs = append(handoffArgs, args)
				return okJSON(map[string]any{"ok": true, "id": "art-1"}), nil
			case "fairy_ingest":
				return okJSON(map[string]any{"ok": true}), nil
			case "analyze_target":
				return okJSON(map[string]any{
					"kind": "pe",
					"path": `C:\lab\sample.exe`,
					"findings": []any{map[string]any{
						"title": "unbounded strcpy", "severity": "high",
						"file": `src\main.c`, "line": 42, "detail": "no bound on the source",
					}},
				}), nil
			}
			return mcp.ToolResult{}, fmt.Errorf("unexpected tool %q", tool)
		},
	}

	mustApply(t, owner, graph.CmdAddNode(graph.NodeSeed{
		Kind:  graph.KindGoal,
		Props: map[string]any{"statement": "只读取证:demo"},
	}))
	// A URL artifact: youkai may register it, never fetch it.
	mustApply(t, owner, graph.CmdAddNode(graph.NodeSeed{
		Kind: graph.KindAsset,
		Props: map[string]any{
			"value": "artifact:http://lab.invalid/tools/a.exe",
			"kind":  "artifact",
			"url":   "http://lab.invalid/tools/a.exe",
		},
	}))

	r, _ := New(Config{Project: "demo", MaxSteps: 4}, owner, fake)
	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(handoffArgs) != 1 {
		t.Fatalf("fairy_handoff called %d times, want 1", len(handoffArgs))
	}
	if v, ok := handoffArgs[0]["confirm"].(bool); ok && v {
		t.Fatal("youkai downloaded a sample (confirm=true) without a human")
	}
	if intentByAction(t, owner.Snapshot(), "analyze_target") != nil {
		t.Fatal("a URL artifact was analysed before anyone fetched it")
	}
	if rep.Stop != StopIdle {
		t.Fatalf("stop = %q (%s), want idle: a URL artifact is a human decision", rep.Stop, rep.Reason)
	}

	// A local artifact: read-only analysis, findings as candidates.
	localPath := `C:\lab\sample.exe`
	mustApply(t, owner, graph.CmdAddNode(graph.NodeSeed{
		Kind: graph.KindAsset,
		Props: map[string]any{
			"value": "artifact:" + localPath,
			"kind":  "artifact",
			"path":  localPath,
		},
	}))
	r2, _ := New(Config{Project: "demo", MaxSteps: 4}, owner, fake)
	rep2, err := r2.Run(context.Background())
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	var ran bool
	for _, s := range rep2.Steps {
		if s.Action == "analyze_target" {
			ran = true
			if !s.OK {
				t.Fatalf("analyze_target failed: %s", s.Err)
			}
			if s.Tier != 1 {
				t.Fatalf("static analysis ran at tier %d", s.Tier)
			}
		}
		if strings.HasPrefix(s.Action, "pwn_") || s.Action == "impact_proof" {
			t.Fatalf("the loop dispatched %q on its own", s.Action)
		}
	}
	if !ran {
		t.Fatalf("no analyze_target step ran; steps=%+v", rep2.Steps)
	}

	g := owner.Snapshot()
	var finding *graph.Node
	for _, n := range g.OfKind(graph.KindFinding) {
		if n.String("where") == `src\main.c:42` {
			finding = n
		}
	}
	if finding == nil {
		t.Fatalf("the file:line finding did not reach the graph")
	}
	if finding.Status() != "candidate" {
		t.Fatalf("finding state = %q, want candidate (never auto-verified)", finding.Status())
	}
	var anchored bool
	for _, a := range g.Anchors(finding.ID) {
		if a == "artifact:"+localPath {
			anchored = true
		}
	}
	if !anchored {
		t.Fatalf("finding is not anchored to the artifact: %v", g.Anchors(finding.ID))
	}
	if n := fake.called("fairy_ingest"); n == 0 {
		t.Fatal("verdex findings were not mirrored into Fairy's ledger")
	}
}
