// Package graph holds youkai's exploration graph: an append-only, replayable
// record of what the brain believed and why.
//
// Nodes are goal / intent / fact / finding / hint. Edges are lineage:
//
//	derives     goal or fact -> the intent it justifies
//	depends_on  intent -> intent that must finish first
//	anchors     youkai node -> a Fairy ledger asset/endpoint id (a string)
//	supports    fact -> the intent/finding it strengthens
//	refutes     fact -> the claim it weakens
//
// The graph is never rewritten. State changes are events, events are folded in
// order, and the fold is what produced the current graph - so a reviewer can
// re-derive every conclusion from .youkai/explore.json alone.
package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"
)

// Kind is a node's role in the exploration.
type Kind string

const (
	KindGoal    Kind = "goal"
	KindIntent  Kind = "intent"
	KindFact    Kind = "fact"
	KindFinding Kind = "finding"
	KindHint    Kind = "hint"
	// KindAsset is the vertex an anchors edge points at: the local stand-in for
	// a Fairy ledger asset/endpoint id (as a string in prop "value"). The design
	// doc lists relations to ledger assets; a relation needs two endpoints, so
	// the asset vertex exists to keep the graph self-contained and replayable
	// without reading Fairy's ledger.
	//
	// Asset nodes are also what the loop derives work from: a host asset yields
	// probe intents, an artifact asset yields Verdex analysis intents.
	KindAsset Kind = "asset"
)

// Edge relations.
const (
	RelDerives   = "derives"
	RelDependsOn = "depends_on"
	RelAnchors   = "anchors"
	RelSupports  = "supports"
	RelRefutes   = "refutes"
)

// Intent lifecycle states.
const (
	StatusTodo          = "todo"
	StatusActive        = "active"
	StatusDone          = "done"
	StatusSkipped       = "skipped"
	StatusBlocked       = "blocked"
	StatusNeedsApproval = "needs_approval"
)

// Event ops. These strings are the on-disk vocabulary; changing one breaks
// replay of every existing log, so they are fixed.
const (
	OpAddNode     = "add_node"
	OpAddEdge     = "add_edge"
	OpSetStatus   = "set_status"
	OpSetApproved = "set_approved"
	OpAddTrace    = "add_trace"
	OpAddFact     = "add_fact"
	// OpSkipped records a write that was correctly refused as a duplicate. It is
	// additive to the documented op set: idempotency must be visible in the log,
	// not silent.
	OpSkipped = "skipped"
)

// Node is one vertex.
type Node struct {
	ID        int64          `json:"id"`
	Kind      Kind           `json:"kind"`
	CreatedAt time.Time      `json:"created_at"`
	Props     map[string]any `json:"props"`
}

// Edge is one lineage link.
type Edge struct {
	From int64  `json:"from"`
	To   int64  `json:"to"`
	Rel  string `json:"rel"`
}

// Event is one line of .youkai/explore.json.
type Event struct {
	Seq     int64           `json:"seq"`
	TS      time.Time       `json:"ts"`
	Op      string          `json:"op"`
	Payload json.RawMessage `json:"payload"`
}

// Graph is the folded state.
type Graph struct {
	Nodes []*Node `json:"nodes"`
	Edges []Edge  `json:"edges"`
	// Seq is the last applied event sequence number.
	Seq int64 `json:"seq"`

	byID   map[int64]*Node
	nextID int64
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{byID: make(map[int64]*Node), nextID: 1}
}

func (g *Graph) ensureIndex() {
	if g.byID != nil {
		return
	}
	g.byID = make(map[int64]*Node, len(g.Nodes))
	for _, n := range g.Nodes {
		if n == nil {
			continue
		}
		if n.Props == nil {
			n.Props = map[string]any{}
		}
		g.byID[n.ID] = n
		if n.ID >= g.nextID {
			g.nextID = n.ID + 1
		}
	}
}

// Node returns a node by id.
func (g *Graph) Node(id int64) (*Node, bool) {
	g.ensureIndex()
	n, ok := g.byID[id]
	return n, ok
}

// NextNodeID reserves the next node id (owner goroutine only).
func (g *Graph) NextNodeID() int64 {
	g.ensureIndex()
	id := g.nextID
	g.nextID++
	return id
}

// OfKind returns nodes of a kind, ordered by id.
func (g *Graph) OfKind(k Kind) []*Node {
	g.ensureIndex()
	var out []*Node
	for _, n := range g.Nodes {
		if n.Kind == k {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// EdgesOf returns the edges touching id (either direction).
func (g *Graph) EdgesOf(id int64) []Edge {
	var out []Edge
	for _, e := range g.Edges {
		if e.From == id || e.To == id {
			out = append(out, e)
		}
	}
	return out
}

// Out returns edges from id with the given relation ("" means any).
func (g *Graph) Out(id int64, rel string) []Edge {
	var out []Edge
	for _, e := range g.Edges {
		if e.From == id && (rel == "" || e.Rel == rel) {
			out = append(out, e)
		}
	}
	return out
}

// Deps lists the intent ids id depends on.
func (g *Graph) Deps(id int64) []int64 {
	var out []int64
	for _, e := range g.Out(id, RelDependsOn) {
		out = append(out, e.To)
	}
	return out
}

// Anchors lists the ledger anchor ids hanging off n.
func (g *Graph) Anchors(id int64) []string {
	var out []string
	for _, e := range g.Out(id, RelAnchors) {
		if t, ok := g.Node(e.To); ok {
			out = append(out, t.String("value"))
		}
	}
	return out
}

// Clone deep-copies the graph. Snapshots are handed to readers so the owner
// goroutine never has to hold a lock while a planner thinks.
func (g *Graph) Clone() *Graph {
	if g == nil {
		return New()
	}
	b, err := json.Marshal(g)
	if err != nil {
		// A graph that cannot be encoded cannot be snapshotted safely.
		cp := New()
		cp.Seq = g.Seq
		return cp
	}
	var cp Graph
	if err := json.Unmarshal(b, &cp); err != nil {
		cp = Graph{}
	}
	cp.byID = nil
	cp.ensureIndex()
	return &cp
}

// MarshalIndent renders the graph for humans.
func (g *Graph) MarshalIndent() ([]byte, error) { return json.MarshalIndent(g, "", "  ") }

// ---- property accessors ----------------------------------------------------
//
// Props come from two sources: in-process construction (real Go types) and
// replay of JSON (numbers become float64). These helpers accept both so callers
// never have to care.

// Prop reads a raw property.
func (n *Node) Prop(key string) any {
	if n == nil || n.Props == nil {
		return nil
	}
	return n.Props[key]
}

// String reads a string property.
func (n *Node) String(key string) string {
	switch v := n.Prop(key).(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// Int reads an integer property.
func (n *Node) Int(key string) int {
	switch v := n.Prop(key).(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		i, _ := v.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(v)
		return i
	default:
		return 0
	}
}

// Bool reads a boolean property.
func (n *Node) Bool(key string) bool {
	switch v := n.Prop(key).(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	case float64:
		return v != 0
	default:
		return false
	}
}

// Strings reads a string slice property.
func (n *Node) Strings(key string) []string {
	switch v := n.Prop(key).(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// Map reads a nested object property (e.g. intent args).
func (n *Node) Map(key string) map[string]any {
	if m, ok := n.Prop(key).(map[string]any); ok {
		return m
	}
	return nil
}

// Status is the intent lifecycle state.
func (n *Node) Status() string {
	s := n.String("status")
	if s == "" {
		return StatusTodo
	}
	return s
}

// ---- event application -----------------------------------------------------

// Apply folds one event into g. It is the single implementation used by both
// replay and live writes, so the two can never diverge.
func (g *Graph) Apply(ev Event) error {
	g.ensureIndex()
	if ev.Seq != g.Seq+1 {
		return fmt.Errorf("event seq %d out of order (graph at %d)", ev.Seq, g.Seq)
	}
	switch ev.Op {
	case OpAddNode, OpAddFact:
		var n Node
		if err := json.Unmarshal(ev.Payload, &n); err != nil {
			return fmt.Errorf("event %d (%s): bad node payload: %w", ev.Seq, ev.Op, err)
		}
		if n.Props == nil {
			n.Props = map[string]any{}
		}
		if _, exists := g.byID[n.ID]; exists {
			return fmt.Errorf("event %d (%s): node %d already exists", ev.Seq, ev.Op, n.ID)
		}
		g.Nodes = append(g.Nodes, &n)
		g.byID[n.ID] = &n
		if n.ID >= g.nextID {
			g.nextID = n.ID + 1
		}

	case OpAddEdge:
		var e Edge
		if err := json.Unmarshal(ev.Payload, &e); err != nil {
			return fmt.Errorf("event %d (add_edge): %w", ev.Seq, err)
		}
		if e.Rel == "" {
			return fmt.Errorf("event %d (add_edge): empty rel", ev.Seq)
		}
		if _, ok := g.byID[e.From]; !ok {
			return fmt.Errorf("event %d (add_edge): unknown from %d", ev.Seq, e.From)
		}
		if _, ok := g.byID[e.To]; !ok {
			return fmt.Errorf("event %d (add_edge): unknown to %d", ev.Seq, e.To)
		}
		g.Edges = append(g.Edges, e)

	case OpSetStatus:
		var p struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return fmt.Errorf("event %d (set_status): %w", ev.Seq, err)
		}
		n, ok := g.byID[p.ID]
		if !ok {
			return fmt.Errorf("event %d (set_status): unknown node %d", ev.Seq, p.ID)
		}
		n.Props["status"] = p.Status

	case OpSetApproved:
		var p struct {
			ID       int64 `json:"id"`
			Approved bool  `json:"approved"`
		}
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return fmt.Errorf("event %d (set_approved): %w", ev.Seq, err)
		}
		n, ok := g.byID[p.ID]
		if !ok {
			return fmt.Errorf("event %d (set_approved): unknown node %d", ev.Seq, p.ID)
		}
		n.Props["approved"] = p.Approved

	case OpAddTrace:
		var p struct {
			ID    int64  `json:"id"`
			Trace string `json:"trace"`
		}
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return fmt.Errorf("event %d (add_trace): %w", ev.Seq, err)
		}
		n, ok := g.byID[p.ID]
		if !ok {
			return fmt.Errorf("event %d (add_trace): unknown node %d", ev.Seq, p.ID)
		}
		// Traces accumulate: a worker may be retried by a human and leave a
		// second trace. Never overwrite evidence.
		prev := n.String("trace")
		if prev == "" {
			n.Props["trace"] = p.Trace
		} else {
			n.Props["trace"] = prev + "\n" + p.Trace
		}

	case OpSkipped:
		// A recorded refusal changes no state by design.

	default:
		return fmt.Errorf("event %d: unknown op %q", ev.Seq, ev.Op)
	}
	g.Seq = ev.Seq
	return nil
}

// Replay folds a JSON Lines event log into a graph.
//
// A missing sequence number is a broken log: someone deleted a line, and any
// conclusion drawn from the remainder is unreliable. Replay refuses rather than
// silently producing a different history.
func Replay(r io.Reader) (*Graph, error) {
	g := New()
	dec := json.NewDecoder(r)
	line := 0
	for {
		var ev Event
		err := dec.Decode(&ev)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("explore.json line %d: %w", line+1, err)
		}
		line++
		if err := g.Apply(ev); err != nil {
			return nil, fmt.Errorf("explore.json line %d: %w", line, err)
		}
	}
	return g, nil
}
