package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"youkai/internal/ledger"
)

// ---- in-memory store -------------------------------------------------------

// fakeStore implements engine.Store closely enough to exercise the control flow
// without PostgreSQL. The real store's guarantees (triggers) are tested against a
// real database in the acceptance suite.
type fakeStore struct {
	mu         sync.Mutex
	assets     []ledger.Asset
	facts      []ledger.Fact
	findings   []ledger.Finding
	intents    []ledger.Intent
	edges      []ledger.Edge
	nextAsset  int64
	nextFact   int64
	nextFind   int64
	nextIntent int64
	finished   string
	scope      json.RawMessage
}

func newFakeStore() *fakeStore { return &fakeStore{} }

func (f *fakeStore) Graph(_ context.Context, _ int64) (ledger.GraphView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ledger.GraphView{
		Engagement: ledger.Engagement{ID: 1, Name: "lab", Scope: f.scope},
		Assets:     append([]ledger.Asset(nil), f.assets...),
		Facts:      append([]ledger.Fact(nil), f.facts...),
		Findings:   append([]ledger.Finding(nil), f.findings...),
		Intents:    append([]ledger.Intent(nil), f.intents...),
		Edges:      append([]ledger.Edge(nil), f.edges...),
	}, nil
}

func (f *fakeStore) EnsureIntent(_ context.Context, engagementID int64, spec ledger.IntentSpec) (ledger.Intent, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fp := ledger.Fingerprint(engagementID, spec.Capability, spec.Args)
	for _, it := range f.intents {
		if it.Fingerprint == fp {
			return it, false, nil
		}
	}
	f.nextIntent++
	it := ledger.Intent{
		ID: f.nextIntent, EngagementID: engagementID, Capability: spec.Capability,
		Args: spec.Args, Tier: spec.Tier, Status: ledger.StatusTodo,
		RequiresApproval: spec.RequiresApproval, Fingerprint: fp,
		Rationale: spec.Rationale, ExpectedFact: spec.ExpectedFact,
		Provenance: spec.Provenance, Inferred: spec.Inferred, GateReason: spec.GateReason,
		Deps: spec.Deps,
	}
	f.intents = append(f.intents, it)
	// Mirror the real store: anchors become asset vertices plus edges, which is
	// what the pending hand-off uses to show supporting evidence.
	for _, a := range spec.Anchors {
		fid := f.upsertAssetLocked(engagementID, a)
		f.edges = append(f.edges, ledger.Edge{
			FromKind: "intent", FromID: it.ID, ToKind: "asset", ToID: fid, Rel: ledger.RelAnchors,
		})
	}
	for _, dep := range spec.Deps {
		f.edges = append(f.edges, ledger.Edge{
			FromKind: "intent", FromID: it.ID, ToKind: "intent", ToID: dep, Rel: ledger.RelDependsOn,
		})
	}
	return it, true, nil
}

// upsertAssetLocked is the caller-holds-the-lock variant.
func (f *fakeStore) upsertAssetLocked(engagementID int64, value string) int64 {
	for _, a := range f.assets {
		if a.Value == value {
			return a.ID
		}
	}
	f.nextAsset++
	kind := "asset"
	if i := strings.Index(value, ":"); i > 0 {
		kind = value[:i]
	}
	f.assets = append(f.assets, ledger.Asset{ID: f.nextAsset, EngagementID: engagementID, Kind: kind, Value: value})
	return f.nextAsset
}

func (f *fakeStore) SetIntentStatus(_ context.Context, _, id int64, status string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.intents {
		if f.intents[i].ID == id {
			f.intents[i].Status = status
			return nil
		}
	}
	return fmt.Errorf("intent %d not found", id)
}

func (f *fakeStore) AppendTrace(_ context.Context, _, id int64, line string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.intents {
		if f.intents[i].ID == id {
			if f.intents[i].Trace == "" {
				f.intents[i].Trace = line
			} else {
				f.intents[i].Trace += "\n" + line
			}
		}
	}
	return nil
}

func (f *fakeStore) Ingest(_ context.Context, engagementID int64, _ *int64, intentID *int64, obs ledger.Observation) (ledger.IngestResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var res ledger.IngestResult
	for _, fct := range obs.Facts {
		dup := false
		for _, existing := range f.facts {
			if existing.Statement == fct.Statement {
				if rid(existing.Evidence) == rid(fct.Evidence) {
					dup = true
					break
				}
			}
		}
		if dup {
			res.Deduped++
			continue
		}
		f.nextFact++
		f.facts = append(f.facts, ledger.Fact{
			ID: f.nextFact, EngagementID: engagementID, Statement: fct.Statement,
			Evidence: fct.Evidence, Tags: fct.Tags, State: "observed",
		})
		res.FactIDs = append(res.FactIDs, f.nextFact)
		res.NewFacts++
		if intentID != nil {
			f.edges = append(f.edges, ledger.Edge{
				FromKind: "intent", FromID: *intentID, ToKind: "fact", ToID: f.nextFact, Rel: ledger.RelSupports,
			})
		}
		for _, a := range fct.Anchors {
			aid := f.upsertAssetLocked(engagementID, a)
			f.edges = append(f.edges, ledger.Edge{
				FromKind: "fact", FromID: f.nextFact, ToKind: "asset", ToID: aid, Rel: ledger.RelAnchors,
			})
		}
	}
	for _, fd := range obs.Findings {
		f.nextFind++
		f.findings = append(f.findings, ledger.Finding{
			ID: f.nextFind, EngagementID: engagementID, Title: fd.Title,
			Severity: fd.Severity, Kind: fd.Kind, Where: fd.Where, Detail: fd.Detail,
			State: ledger.FindingCandidate, Evidence: fd.Evidence, Tags: fd.Tags,
		})
		res.FindingIDs = append(res.FindingIDs, f.nextFind)
	}
	return res, nil
}

func (f *fakeStore) UpsertAsset(_ context.Context, engagementID int64, seed ledger.AssetSeed) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.assets {
		if a.Kind == seed.Kind && a.Value == seed.Value {
			return a.ID, nil
		}
	}
	f.nextAsset++
	f.assets = append(f.assets, ledger.Asset{
		ID: f.nextAsset, EngagementID: engagementID, Kind: seed.Kind, Value: seed.Value, Props: seed.Props,
	})
	return f.nextAsset, nil
}

func (f *fakeStore) FinishRun(_ context.Context, _ int64, status, reason string, _, _ int) error {
	f.finished = status + ": " + reason
	return nil
}

func (f *fakeStore) intentByCapability(capability string) *ledger.Intent {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.intents {
		if f.intents[i].Capability == capability {
			return &f.intents[i]
		}
	}
	return nil
}

func (f *fakeStore) countIntents() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.intents)
}

func rid(m map[string]any) string {
	if m == nil {
		return ""
	}
	s, _ := m["request_id"].(string)
	return s
}

// ---- fake dispatcher -------------------------------------------------------

type dispatchCall struct {
	Capability string
	Args       map[string]any
}

type fakeDispatcher struct {
	mu      sync.Mutex
	calls   []dispatchCall
	handler func(capability string, args map[string]any) (ledger.Observation, error)
}

func (d *fakeDispatcher) Run(_ context.Context, _ int64, capability string, args map[string]any) (ledger.Observation, error) {
	d.mu.Lock()
	d.calls = append(d.calls, dispatchCall{Capability: capability, Args: args})
	d.mu.Unlock()
	if d.handler == nil {
		return ledger.Observation{}, nil
	}
	return d.handler(capability, args)
}

func (d *fakeDispatcher) count(capability string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, c := range d.calls {
		if c.Capability == capability {
			n++
		}
	}
	return n
}

func (d *fakeDispatcher) all() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.calls))
	for _, c := range d.calls {
		out = append(out, c.Capability)
	}
	return out
}

// ---- helpers ---------------------------------------------------------------

func newEngine(t *testing.T, store *fakeStore, disp *fakeDispatcher, cfg Config) *Engine {
	t.Helper()
	cfg.Store = store
	cfg.Dispatcher = disp
	cfg.EngagementID = 1
	cfg.Engagement = "lab"
	if cfg.MaxSteps == 0 {
		cfg.MaxSteps = 6
	}
	cfg.Concurrency = 2
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func scopeJSON(t *testing.T, include ...string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"project": "lab", "include": include, "basis": "self-hosted lab",
		"operator": "tester", "allow_private": true,
	})
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	return b
}

// ---- the acceptance tests --------------------------------------------------

// TestDeriveBootstrapAndIdempotence: targets come from the scope passport, and
// deriving twice adds nothing.
func TestDeriveBootstrapAndIdempotence(t *testing.T) {
	store := newFakeStore()
	disp := &fakeDispatcher{handler: func(c string, _ map[string]any) (ledger.Observation, error) {
		return ledger.Observation{RequestIDs: []string{"R0001-aa"}}, nil
	}}
	store.scope = scopeJSON(t, "127.0.0.1:8080")
	e := newEngine(t, store, disp, Config{MaxSteps: 1})

	n, err := e.derive(context.Background())
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if n == 0 {
		t.Fatal("bootstrap derived nothing")
	}
	gv, _ := store.Graph(context.Background(), 1)
	if len(gv.Assets) == 0 {
		t.Fatal("no host asset created from the scope")
	}
	first := store.countIntents()
	if first == 0 {
		t.Fatal("no intents derived")
	}
	// A second tick must not fork the graph.
	if _, err := e.derive(context.Background()); err != nil {
		t.Fatalf("second derive: %v", err)
	}
	if got := store.countIntents(); got != first {
		t.Fatalf("derive is not idempotent: %d -> %d intents", first, got)
	}
}

// TestRunsReadOnlyChainThenStopsAtTierTwo is the headline acceptance test.
func TestRunsReadOnlyChainThenStopsAtTierTwo(t *testing.T) {
	store := newFakeStore()
	dispatcher := &fakeDispatcher{}
	dispatcher.handler = func(capability string, args map[string]any) (ledger.Observation, error) {
		switch capability {
		case "probe":
			url, _ := args["url"].(string)
			return ledger.Observation{
				Facts: []ledger.FactSeed{
					{
						Statement: "GET " + url + " -> 200",
						Evidence:  map[string]any{"request_id": "R0001-aa", "url": url, "status": 200},
						Tags:      []string{"probe", "http"},
						Anchors:   []string{"host:127.0.0.1"},
					},
					{
						Statement: "git 配置可读:" + url,
						Evidence:  map[string]any{"request_id": "R0001-aa", "url": url},
						Tags:      []string{"git", "exposed"},
						Anchors:   []string{"host:127.0.0.1"},
					},
				},
				RequestIDs: []string{"R0001-aa"},
			}, nil
		case "scan":
			return ledger.Observation{
				Facts: []ledger.FactSeed{{
					Statement: "参数反射待浏览器复核:GET http://127.0.0.1:8080/s?q=1 (param: q)",
					Evidence: map[string]any{
						"request_id": "R0002-bb",
						"where":      "GET http://127.0.0.1:8080/s?q=1 (param: q)",
						"url":        "http://127.0.0.1:8080/s?q=1",
					},
					Tags:    []string{"reflects", "param-candidate"},
					Anchors: []string{"host:127.0.0.1"},
				}},
				Findings: []ledger.FindingSeed{{
					Title: "参数 q 的值反射进响应", Severity: "medium", Kind: "reflection",
					Where:    "GET http://127.0.0.1:8080/s?q=1 (param: q)",
					Evidence: map[string]any{"request_id": "R0002-bb"},
				}},
				RequestIDs: []string{"R0002-bb"},
			}, nil
		}
		return ledger.Observation{}, fmt.Errorf("unexpected capability %q", capability)
	}

	e := newEngine(t, store, dispatcher, Config{
		MaxSteps: 6,
		SeedURLs: []string{"http://127.0.0.1:8080"},
	})
	rep, err := e.Run(context.Background(), 7)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if rep.Stop != StopNeedsApproval {
		t.Fatalf("stop = %q (%s), want needs_approval", rep.Stop, rep.Reason)
	}
	if len(rep.Steps) < 2 {
		t.Fatalf("expected the read-only chain to run, got %v", dispatcher.all())
	}
	for _, s := range rep.Steps {
		if s.Tier != 1 {
			t.Fatalf("%s ran at tier %d", s.Capability, s.Tier)
		}
		if !s.OK {
			t.Fatalf("%s failed: %s", s.Capability, s.Err)
		}
	}
	// The tier-2 step was derived and parked, never dispatched.
	if n := dispatcher.count("param"); n != 0 {
		t.Fatalf("tier-2 param dispatched %d time(s)", n)
	}
	param := store.intentByCapability("param")
	if param == nil {
		t.Fatal("the tier-2 follow-up was not derived")
	}
	if param.Status != ledger.StatusNeedsApproval {
		t.Fatalf("param intent status = %q", param.Status)
	}
	if param.Tier != 2 {
		t.Fatalf("param intent tier = %d", param.Tier)
	}
	if len(rep.Pending) == 0 {
		t.Fatal("no pending hand-off")
	}
	p := rep.Pending[0]
	if p.Capability != "param" || p.ExactRequest == "" || p.MinImpact == "" || p.StopCondition == "" {
		t.Fatalf("pending is missing the four evidence fields: %+v", p)
	}
	if !strings.Contains(strings.Join(p.Evidence, " "), "param: q") {
		t.Fatalf("pending has no supporting evidence: %v", p.Evidence)
	}
	if store.finished == "" || !strings.Contains(store.finished, StopNeedsApproval) {
		t.Fatalf("run was not closed with the stop reason: %q", store.finished)
	}
}

// TestSensitiveStopsTheRun.
func TestSensitiveStopsTheRun(t *testing.T) {
	store := newFakeStore()
	dispatcher := &fakeDispatcher{handler: func(capability string, _ map[string]any) (ledger.Observation, error) {
		if capability == "probe" {
			return ledger.Observation{
				Facts: []ledger.FactSeed{{
					Statement: "probe body contained a leaked key",
					Evidence:  map[string]any{"request_id": "R1", "preview": "-----BEGIN RSA PRIVATE KEY-----"},
					Tags:      []string{"probe"},
				}},
				RequestIDs: []string{"R1"},
			}, nil
		}
		return ledger.Observation{}, nil
	}}
	e := newEngine(t, store, dispatcher, Config{MaxSteps: 4, SeedURLs: []string{"http://127.0.0.1:8080"}})
	rep, err := e.Run(context.Background(), 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Stop != StopSensitive {
		t.Fatalf("stop = %q (%s), want sensitive_stop", rep.Stop, rep.Reason)
	}
	if rep.Sensitive == nil || rep.Sensitive.Name != "private-key" {
		t.Fatalf("sensitive hit = %+v", rep.Sensitive)
	}
	if strings.Contains(rep.Reason, "PRIVATE KEY") {
		t.Fatal("the report echoed the secret")
	}
}

// TestFailureIsNotRetried.
func TestFailureIsNotRetried(t *testing.T) {
	store := newFakeStore()
	dispatcher := &fakeDispatcher{handler: func(capability string, _ map[string]any) (ledger.Observation, error) {
		if capability == "probe" {
			return ledger.Observation{}, fmt.Errorf("connection refused")
		}
		return ledger.Observation{}, nil
	}}
	e := newEngine(t, store, dispatcher, Config{MaxSteps: 4, SeedURLs: []string{"http://127.0.0.1:8080"}})
	rep, err := e.Run(context.Background(), 1)
	if err != nil {
		t.Fatalf("a capability error must not fail the run: %v", err)
	}
	if n := dispatcher.count("probe"); n != 1 {
		t.Fatalf("probe was retried: %d calls", n)
	}
	probe := store.intentByCapability("probe")
	if probe.Status != ledger.StatusActive {
		t.Fatalf("failed intent status = %q, want active", probe.Status)
	}
	var sawErr bool
	for _, s := range rep.Steps {
		if s.Capability == "probe" && s.Err != "" {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatal("the failed step was not reported")
	}
}

// TestMaxSteps.
func TestMaxSteps(t *testing.T) {
	store := newFakeStore()
	dispatcher := &fakeDispatcher{handler: func(string, map[string]any) (ledger.Observation, error) {
		return ledger.Observation{}, nil
	}}
	e := newEngine(t, store, dispatcher, Config{MaxSteps: 1, Concurrency: 1, SeedURLs: []string{"http://127.0.0.1:8080"}})
	rep, err := e.Run(context.Background(), 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Stop != StopMaxSteps {
		t.Fatalf("stop = %q, want max_steps", rep.Stop)
	}
	if len(rep.Steps) != 1 {
		t.Fatalf("ran %d steps with max_steps=1", len(rep.Steps))
	}
}

// TestIdleWithoutContext.
func TestIdleWithoutContext(t *testing.T) {
	store := newFakeStore()
	dispatcher := &fakeDispatcher{}
	e := newEngine(t, store, dispatcher, Config{MaxSteps: 3})
	rep, err := e.Run(context.Background(), 1)
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

// TestApprovedTierTwoStillNeverRuns: a boolean in the database is not a human.
func TestApprovedTierTwoStillNeverRuns(t *testing.T) {
	store := newFakeStore()
	dispatcher := &fakeDispatcher{handler: func(string, map[string]any) (ledger.Observation, error) {
		return ledger.Observation{}, nil
	}}
	_, _, err := store.EnsureIntent(context.Background(), 1, ledger.IntentSpec{
		Capability: "param", Args: map[string]any{"url": "http://127.0.0.1:8080/s", "param": "q"},
		Tier: 2, RequiresApproval: true,
	})
	if err != nil {
		t.Fatalf("seed intent: %v", err)
	}
	// Simulate a row that claims approval.
	store.mu.Lock()
	store.intents[0].Approved = true
	store.mu.Unlock()

	e := newEngine(t, store, dispatcher, Config{MaxSteps: 3})
	rep, err := e.Run(context.Background(), 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Stop != StopNeedsApproval {
		t.Fatalf("stop = %q, want needs_approval", rep.Stop)
	}
	if n := dispatcher.count("param"); n != 0 {
		t.Fatalf("approved=true let the engine run tier2 (%d calls)", n)
	}
}

// TestProposalNeedsProvenance.
func TestProposalNeedsProvenance(t *testing.T) {
	store := newFakeStore()
	dispatcher := &fakeDispatcher{}
	proposer := &fakeProposer{specs: []ledger.IntentSpec{
		{Capability: "scan", Args: map[string]any{"url": "http://127.0.0.1:8080"}}, // no provenance
		{Capability: "probe", Args: map[string]any{"url": "http://127.0.0.1:8080/x", "method": "GET"}, Provenance: "planner#1"},
	}}
	e := newEngine(t, store, dispatcher, Config{MaxSteps: 1, Proposer: proposer})
	if _, err := e.Run(context.Background(), 1); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if store.intentByCapability("scan") != nil {
		t.Fatal("a proposal without an archive was admitted")
	}
	got := store.intentByCapability("probe")
	if got == nil {
		t.Fatal("an archived proposal was not admitted")
	}
	if !got.Inferred || got.Provenance != "planner#1" {
		t.Fatalf("provenance not recorded: %+v", got)
	}
}

type fakeProposer struct{ specs []ledger.IntentSpec }

func (p *fakeProposer) Propose(context.Context, ProposeRequest) ([]ledger.IntentSpec, error) {
	return p.specs, nil
}

// ---- unit tests for the helpers --------------------------------------------

func TestParseWhereParam(t *testing.T) {
	cases := []struct{ in, url, param string }{
		{"GET http://127.0.0.1:8080/s?q=1 (param: q)", "http://127.0.0.1:8080/s?q=1", "q"},
		{"参数反射待浏览器复核:GET https://lab.invalid/x?u=2 (param: u)", "https://lab.invalid/x?u=2", "u"},
	}
	for _, c := range cases {
		u, p, ok := parseWhereParam(c.in)
		if !ok || u != c.url || p != c.param {
			t.Fatalf("parseWhereParam(%q) = %q,%q,%v", c.in, u, p, ok)
		}
	}
	if _, _, ok := parseWhereParam("nothing here"); ok {
		t.Fatal("invented a target")
	}
}

func TestScopeSurfaces(t *testing.T) {
	got := scopeSurfaces(scopeJSON(t, "127.0.0.1:8080", "https://lab.invalid/api", "*.example.com", "10.0.0.0/24"))
	if len(got) != 2 {
		t.Fatalf("surfaces = %v, want 2 (wildcard and CIDR are not surfaces)", got)
	}
	if got[0] != "https://127.0.0.1:8080" && got[1] != "https://127.0.0.1:8080" {
		t.Fatalf("loopback surface missing: %v", got)
	}
}

func TestSensitiveScan(t *testing.T) {
	cases := []struct {
		text string
		want bool
		name string
	}{
		{"nothing", false, ""},
		{"-----BEGIN OPENSSH PRIVATE KEY-----", true, "private-key"},
		{"AKIAIOSFODNN7EXAMPLE", true, "aws-access-key"},
		{"ghp_0123456789012345678901234567890123456789", true, "github-token"},
		{`password: "hunter2hunter2"`, true, "password-literal"},
	}
	for _, c := range cases {
		hit, ok := ScanSensitive(c.text)
		if ok != c.want {
			t.Fatalf("ScanSensitive(%q) = %v", c.text, ok)
		}
		if ok && hit.Name != c.name {
			t.Fatalf("ScanSensitive(%q) name = %q, want %q", c.text, hit.Name, c.name)
		}
	}
}

// SearchTraces is the read side of the fake store: the engine may ask what it has
// already done (the v0.7 derivation guard). The fake keeps the same projection
// shape so the guard is exercised, not bypassed.
func (f *fakeStore) SearchTraces(_ context.Context, engagementID int64, q ledger.TraceQuery) ([]ledger.TraceHit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ledger.TraceHit
	for _, it := range f.intents {
		if it.EngagementID != engagementID || it.Trace == "" {
			continue
		}
		if q.Capability != "" && it.Capability != q.Capability {
			continue
		}
		target := ledger.TargetKey(it.Args)
		out = append(out, ledger.TraceHit{
			IntentID: it.ID, Capability: it.Capability, Tier: it.Tier,
			Status: it.Status, Target: target, Summary: it.Trace,
		})
	}
	return out, nil
}

// TestDeriveDoesNotRepeatACoveredCheck is the v0.7 acceptance test for the guard:
// a check whose trace says it already ran is not derived again.
func TestDeriveDoesNotRepeatACoveredCheck(t *testing.T) {
	store := newFakeStore()
	store.scope = scopeJSON(t, "127.0.0.1:18080")
	e := newEngine(t, store, &fakeDispatcher{}, Config{MaxSteps: 1})

	// Seed the trail as if a probe already ran against the git path.
	it, _, err := store.EnsureIntent(context.Background(), 1, ledger.IntentSpec{
		Capability: "probe",
		Args:       map[string]any{"url": "http://127.0.0.1:18080/.git/config"},
		Tier:       1,
	})
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := store.SetIntentStatus(context.Background(), 1, it.ID, ledger.StatusDone); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := store.AppendTrace(context.Background(), 1, it.ID,
		"capability=probe ok=true tier=1 facts=1 findings=1 request_ids=R0001-aaaa"); err != nil {
		t.Fatalf("trace: %v", err)
	}

	if _, err := e.derive(context.Background()); err != nil {
		t.Fatalf("derive: %v", err)
	}
	// Other rules may still derive new work (the scan of the surface, for instance);
	// what must NOT happen is a second probe of the same endpoint.
	probes := 0
	for _, it := range store.intents {
		if it.Capability != "probe" {
			continue
		}
		if u, _ := it.Args["url"].(string); strings.Contains(u, "/.git/config") {
			probes++
		}
	}
	if probes != 1 {
		t.Fatalf("probe intents for the covered endpoint = %d, want 1 (the guard failed)", probes)
	}
}
