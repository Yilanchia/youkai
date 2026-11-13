package graph

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func openTemp(t *testing.T) (*Owner, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".youkai", "explore.json")
	o, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return o, path
}

func mustAddNode(t *testing.T, o *Owner, seed NodeSeed) int64 {
	t.Helper()
	res, err := o.Apply(CmdAddNode(seed))
	if err != nil {
		t.Fatalf("add_node %v: %v", seed.Kind, err)
	}
	return res.NodeID
}

// TestConcurrentApplyReplayMatchesMemory is the module-2 acceptance test:
// 100 concurrent writes, then replay must reproduce the identical graph with a
// contiguous sequence.
func TestConcurrentApplyReplayMatchesMemory(t *testing.T) {
	o, path := openTemp(t)

	const n = 100
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			switch i % 3 {
			case 0:
				_, err = o.Apply(CmdAddNode(NodeSeed{
					Kind:  KindIntent,
					Props: map[string]any{"action": "web_probe", "tier": 1, "n": i},
				}))
			case 1:
				_, err = o.Apply(CmdAddFact(FactSeed{
					Statement: "concurrent fact " + itoa(i),
					Evidence:  map[string]any{"request_id": "req-" + itoa(i)},
					Tags:      []string{"test"},
				}))
			default:
				_, err = o.Apply(CmdAddNode(NodeSeed{
					Kind:  KindHint,
					Props: map[string]any{"note": itoa(i)},
				}))
			}
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Apply: %v", err)
	}

	mem := o.Snapshot()
	if mem.Seq != n {
		t.Fatalf("in-memory seq = %d, want %d", mem.Seq, n)
	}
	if err := o.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	replayed, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer replayed.Close()
	got := replayed.Snapshot()

	if got.Seq != mem.Seq {
		t.Fatalf("replayed seq = %d, in-memory %d", got.Seq, mem.Seq)
	}
	if len(got.Nodes) != len(mem.Nodes) {
		t.Fatalf("replayed %d nodes, in-memory %d", len(got.Nodes), len(mem.Nodes))
	}
	if len(got.Edges) != len(mem.Edges) {
		t.Fatalf("replayed %d edges, in-memory %d", len(got.Edges), len(mem.Edges))
	}
	a := mustJSON(t, mem)
	b := mustJSON(t, got)
	if !bytes.Equal(a, b) {
		t.Fatalf("replayed graph differs from in-memory graph\n--memory--\n%s\n--replay--\n%s", a, b)
	}

	// Sequence numbers must be contiguous with no holes.
	events := readEvents(t, path)
	for i, ev := range events {
		if ev.Seq != int64(i+1) {
			t.Fatalf("event %d has seq %d: log has a hole", i, ev.Seq)
		}
	}
}

// TestFactIdempotent is the second module-2 acceptance: the same fact twice
// yields one node and one recorded skip.
func TestFactIdempotent(t *testing.T) {
	o, path := openTemp(t)
	seed := FactSeed{
		Statement: "git config readable on lab.invalid",
		Evidence:  map[string]any{"request_id": "req-42"},
		Tags:      []string{"git"},
	}

	first, err := o.Apply(CmdAddFact(seed))
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second, err := o.Apply(CmdAddFact(seed))
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if second.Deduped != true {
		t.Fatal("duplicate fact was not deduplicated")
	}
	if second.NodeID != first.NodeID {
		t.Fatalf("dedup returned node %d, want the original %d", second.NodeID, first.NodeID)
	}
	if n := len(o.Snapshot().OfKind(KindFact)); n != 1 {
		t.Fatalf("graph holds %d facts, want 1", n)
	}
	_ = o.Close()

	var skipped int
	for _, ev := range readEvents(t, path) {
		if ev.Op == OpSkipped {
			skipped++
		}
	}
	if skipped != 1 {
		t.Fatalf("log records %d skipped events, want 1", skipped)
	}

	// A different request_id is a different fact and must be kept.
	o2, _ := Open(path)
	defer o2.Close()
	seed.Evidence = map[string]any{"request_id": "req-43"}
	res, err := o2.Apply(CmdAddFact(seed))
	if err != nil {
		t.Fatalf("third apply: %v", err)
	}
	if res.Deduped {
		t.Fatal("fact with a new request_id was wrongly deduplicated")
	}
}

// TestBrokenLogIsDetected is the third module-2 acceptance: deleting a line must
// be reported, not silently folded into a different history.
func TestBrokenLogIsDetected(t *testing.T) {
	o, path := openTemp(t)
	for i := 0; i < 3; i++ {
		mustAddNode(t, o, NodeSeed{Kind: KindHint, Props: map[string]any{"i": i}})
	}
	_ = o.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("expected 3 events, got %d", len(lines))
	}
	tampered := append(append([][]byte{}, lines[0]), lines[2]) // drop the middle event
	if err := os.WriteFile(path, append(bytes.Join(tampered, []byte("\n")), '\n'), 0o644); err != nil {
		t.Fatalf("write tampered log: %v", err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted a log with a deleted event")
	}
}

func TestDependsAndAnchors(t *testing.T) {
	o, _ := openTemp(t)
	defer o.Close()

	a := mustAddNode(t, o, NodeSeed{Kind: KindIntent, Props: map[string]any{"action": "web_probe"}})
	b := mustAddNode(t, o, NodeSeed{
		Kind:    KindIntent,
		Props:   map[string]any{"action": "analyze_target"},
		Deps:    []int64{a},
		Anchors: []string{"host:lab.invalid"},
	})

	g := o.Snapshot()
	if deps := g.Deps(b); len(deps) != 1 || deps[0] != a {
		t.Fatalf("deps = %v, want [%d]", deps, a)
	}
	if anchors := g.Anchors(b); len(anchors) != 1 || anchors[0] != "host:lab.invalid" {
		t.Fatalf("anchors = %v", anchors)
	}
	// Anchoring to the same value from two nodes must reuse one asset vertex.
	c := mustAddNode(t, o, NodeSeed{Kind: KindFact, Props: map[string]any{"statement": "x"}, Anchors: []string{"host:lab.invalid"}})
	g = o.Snapshot()
	if n := len(g.OfKind(KindAsset)); n != 1 {
		t.Fatalf("asset vertices = %d, want 1 (id %d)", n, c)
	}
}

func TestStatusTransitionsAreAppended(t *testing.T) {
	o, _ := openTemp(t)
	defer o.Close()

	id := mustAddNode(t, o, NodeSeed{Kind: KindIntent, Props: map[string]any{"action": "web_probe"}})
	if st := nodeOf(t, o.Snapshot(), id).Status(); st != StatusTodo {
		t.Fatalf("new intent status = %q, want todo", st)
	}
	if _, err := o.Apply(CmdSetStatus(id, StatusActive)); err != nil {
		t.Fatalf("set_status: %v", err)
	}
	if _, err := o.Apply(CmdSetStatus(id, StatusDone)); err != nil {
		t.Fatalf("set_status: %v", err)
	}
	if _, err := o.Apply(CmdSetApproved(id, true)); err != nil {
		t.Fatalf("set_approved: %v", err)
	}
	if _, err := o.Apply(CmdAddTrace(id, "step 1 ok")); err != nil {
		t.Fatalf("add_trace: %v", err)
	}
	if _, err := o.Apply(CmdAddTrace(id, "human retry: ok")); err != nil {
		t.Fatalf("add_trace: %v", err)
	}

	g := o.Snapshot()
	n := nodeOf(t, g, id)
	if n.Status() != StatusDone {
		t.Fatalf("status = %q", n.Status())
	}
	if !n.Bool("approved") {
		t.Fatal("approved flag not recorded")
	}
	want := "step 1 ok\nhuman retry: ok"
	if got := n.String("trace"); got != want {
		t.Fatalf("trace = %q, want %q (traces accumulate, never overwrite)", got, want)
	}
}

func TestUnknownReferencesRejected(t *testing.T) {
	o, _ := openTemp(t)
	defer o.Close()

	if _, err := o.Apply(CmdSetStatus(999, StatusDone)); err == nil {
		t.Fatal("set_status accepted an unknown node")
	}
	if _, err := o.Apply(CmdAddNode(NodeSeed{Kind: KindIntent, Deps: []int64{999}})); err == nil {
		t.Fatal("add_node accepted a missing dependency")
	}
	if _, err := o.Apply(CmdAddEdge(1, 999, RelSupports)); err == nil {
		t.Fatal("add_edge accepted a missing endpoint")
	}
	if _, err := o.Apply(CmdAddNode(NodeSeed{})); err == nil {
		t.Fatal("add_node accepted an empty kind")
	}
	if _, err := o.Apply(CmdAddFact(FactSeed{})); err == nil {
		t.Fatal("add_fact accepted an empty statement")
	}
}

func TestSubscribeFiresOnWrite(t *testing.T) {
	o, _ := openTemp(t)
	defer o.Close()

	ch := o.Subscribe()
	mustAddNode(t, o, NodeSeed{Kind: KindHint, Props: map[string]any{"a": 1}})
	select {
	case <-ch:
	default:
		t.Fatal("subscriber was not notified")
	}
	// Signalling must not block when nobody reads: fill the buffer, write more.
	mustAddNode(t, o, NodeSeed{Kind: KindHint, Props: map[string]any{"a": 2}})
	mustAddNode(t, o, NodeSeed{Kind: KindHint, Props: map[string]any{"a": 3}})
}

func TestClosedOwnerRejectsWork(t *testing.T) {
	o, _ := openTemp(t)
	if err := o.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := o.Apply(CmdAddNode(NodeSeed{Kind: KindHint})); err == nil {
		t.Fatal("closed owner accepted a write")
	}
	if g := o.Snapshot(); g == nil {
		t.Fatal("Snapshot on closed owner returned nil")
	}
}

func TestGraphCloneIsIndependent(t *testing.T) {
	o, _ := openTemp(t)
	defer o.Close()
	mustAddNode(t, o, NodeSeed{Kind: KindHint, Props: map[string]any{"k": "v"}})

	snap := o.Snapshot()
	snap.Nodes[0].Props["k"] = "mutated"
	if got := o.Snapshot().Nodes[0].String("k"); got != "v" {
		t.Fatalf("mutating a snapshot changed the owner's graph (%q)", got)
	}
}

func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var out []Event
	for {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			break
		}
		out = append(out, ev)
	}
	return out
}

func nodeOf(t *testing.T, g *Graph, id int64) *Node {
	t.Helper()
	n, ok := g.Node(id)
	if !ok {
		t.Fatalf("node %d missing", id)
	}
	return n
}

func mustJSON(t *testing.T, g *Graph) []byte {
	t.Helper()
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}
	return b
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
