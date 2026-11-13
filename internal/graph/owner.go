package graph

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrClosed is returned by operations on a closed owner.
var ErrClosed = errors.New("graph: owner closed")

// ApplyResult reports what one write did.
type ApplyResult struct {
	// NodeID is the node this command created or touched (0 for edges).
	NodeID int64
	// Deduped is true when an idempotent write was correctly refused because the
	// fact already existed. The refusal itself is logged.
	Deduped bool
}

// NodeSeed describes a node to create.
type NodeSeed struct {
	Kind  Kind
	Props map[string]any
	// Deps are intent ids that must reach done/skipped before this one is
	// claimable. Each becomes a depends_on edge.
	Deps []int64
	// Anchors are Fairy ledger anchors (asset / endpoint ids). Each becomes an
	// anchors edge to an asset node with that value.
	Anchors []string
}

// FactSeed describes an observed fact. Facts are the only thing workers are
// allowed to produce: normalised, reviewable statements - never raw response
// bodies.
type FactSeed struct {
	Statement string
	// Evidence must carry at least a request_id or an audit location; the owner
	// does not enforce it, the loop's normaliser builds it that way.
	Evidence map[string]any
	Tags     []string
	Anchors  []string
}

// Command is one mutation. The owner goroutine is the only thing that executes
// these, serially, in submission order.
type Command struct {
	Op string

	Node     *NodeSeed
	Fact     *FactSeed
	Edge     *Edge
	Target   int64
	Status   string
	Approved bool
	Trace    string
}

// CmdAddNode creates a node plus its dependency and anchor edges.
func CmdAddNode(seed NodeSeed) Command { return Command{Op: OpAddNode, Node: &seed} }

// CmdAddFact records an observed fact (idempotent on statement+request_id).
func CmdAddFact(seed FactSeed) Command { return Command{Op: OpAddFact, Fact: &seed} }

// CmdAddEdge links two existing nodes.
func CmdAddEdge(from, to int64, rel string) Command {
	return Command{Op: OpAddEdge, Edge: &Edge{From: from, To: to, Rel: rel}}
}

// CmdSetStatus moves an intent through its lifecycle.
func CmdSetStatus(id int64, status string) Command {
	return Command{Op: OpSetStatus, Target: id, Status: status}
}

// CmdSetApproved records a human approval. The loop never executes tier2 even
// when this is true; approval only unlocks the human path.
func CmdSetApproved(id int64, approved bool) Command {
	return Command{Op: OpSetApproved, Target: id, Approved: approved}
}

// CmdAddTrace appends worker trace text to an intent.
func CmdAddTrace(id int64, trace string) Command {
	return Command{Op: OpAddTrace, Target: id, Trace: trace}
}

// Owner serialises every write to the graph and to .youkai/explore.json.
//
// Exactly one goroutine touches *Graph and the file. Everything else goes
// through Apply. There is no lock around the graph because there is no sharing.
type Owner struct {
	path string

	applyCh chan applyReq
	snapCh  chan chan *Graph
	quit    chan struct{}
	done    chan struct{}

	graph  *Graph
	file   *os.File
	writer *bufio.Writer

	subMu sync.Mutex
	subs  []chan struct{}

	closeOnce sync.Once
}

type applyReq struct {
	cmd   Command
	reply chan response
}

type response struct {
	res ApplyResult
	err error
}

// Open loads (or creates) the append-only log at path and starts the owner.
func Open(path string) (*Owner, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("graph: create %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("graph: open %s: %w", path, err)
	}

	g, err := Replay(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("graph: %s is not a valid append-only log: %w", path, err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("graph: seek %s: %w", path, err)
	}

	o := &Owner{
		path:    path,
		applyCh: make(chan applyReq),
		snapCh:  make(chan chan *Graph),
		quit:    make(chan struct{}),
		done:    make(chan struct{}),
		graph:   g,
		file:    f,
		writer:  bufio.NewWriterSize(f, 64<<10),
	}
	go o.loop()
	return o, nil
}

// Path is the log file this owner appends to.
func (o *Owner) Path() string { return o.path }

func (o *Owner) loop() {
	defer close(o.done)
	for {
		select {
		case req := <-o.applyCh:
			res, err := o.apply(req.cmd)
			req.reply <- response{res: res, err: err}
			if err == nil {
				o.broadcast()
			}
		case ch := <-o.snapCh:
			ch <- o.graph.Clone()
		case <-o.quit:
			_ = o.writer.Flush()
			_ = o.file.Sync()
			return
		}
	}
}

// Apply runs one command synchronously on the owner goroutine and flushes the
// event to disk before returning, so a crash cannot lose an acknowledged write.
func (o *Owner) Apply(cmd Command) (ApplyResult, error) {
	reply := make(chan response, 1)
	select {
	case o.applyCh <- applyReq{cmd: cmd, reply: reply}:
	case <-o.done:
		return ApplyResult{}, ErrClosed
	}
	select {
	case r := <-reply:
		return r.res, r.err
	case <-o.done:
		return ApplyResult{}, ErrClosed
	}
}

// Snapshot returns a deep copy of the current graph for readers.
func (o *Owner) Snapshot() *Graph {
	ch := make(chan *Graph, 1)
	select {
	case o.snapCh <- ch:
	case <-o.done:
		return New()
	}
	select {
	case g := <-ch:
		return g
	case <-o.done:
		return New()
	}
}

// Subscribe returns a channel that receives a non-blocking signal after every
// successful write. A slow subscriber loses signals rather than blocking the
// owner; downstream is expected to debounce.
func (o *Owner) Subscribe() <-chan struct{} {
	ch := make(chan struct{}, 1)
	o.subMu.Lock()
	o.subs = append(o.subs, ch)
	o.subMu.Unlock()
	return ch
}

func (o *Owner) broadcast() {
	o.subMu.Lock()
	subs := o.subs
	o.subMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Close flushes, syncs and stops the owner.
func (o *Owner) Close() error {
	var err error
	o.closeOnce.Do(func() {
		close(o.quit)
		<-o.done
		if o.file != nil {
			err = o.file.Close()
		}
	})
	return err
}

// ---- the only place events are produced ------------------------------------

func (o *Owner) apply(cmd Command) (ApplyResult, error) {
	switch cmd.Op {
	case OpAddNode:
		return o.applyAddNode(cmd)
	case OpAddFact:
		return o.applyAddFact(cmd)
	case OpAddEdge:
		if cmd.Edge == nil {
			return ApplyResult{}, errors.New("add_edge: missing edge")
		}
		if err := o.writeEvent(OpAddEdge, cmd.Edge); err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{}, nil
	case OpSetStatus:
		if cmd.Status == "" {
			return ApplyResult{}, errors.New("set_status: empty status")
		}
		if _, ok := o.graph.Node(cmd.Target); !ok {
			return ApplyResult{}, fmt.Errorf("set_status: unknown node %d", cmd.Target)
		}
		if err := o.writeEvent(OpSetStatus, map[string]any{
			"id": cmd.Target, "status": cmd.Status,
		}); err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{NodeID: cmd.Target}, nil
	case OpSetApproved:
		if _, ok := o.graph.Node(cmd.Target); !ok {
			return ApplyResult{}, fmt.Errorf("set_approved: unknown node %d", cmd.Target)
		}
		if err := o.writeEvent(OpSetApproved, map[string]any{
			"id": cmd.Target, "approved": cmd.Approved,
		}); err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{NodeID: cmd.Target}, nil
	case OpAddTrace:
		if _, ok := o.graph.Node(cmd.Target); !ok {
			return ApplyResult{}, fmt.Errorf("add_trace: unknown node %d", cmd.Target)
		}
		if err := o.writeEvent(OpAddTrace, map[string]any{
			"id": cmd.Target, "trace": cmd.Trace,
		}); err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{NodeID: cmd.Target}, nil
	default:
		return ApplyResult{}, fmt.Errorf("unknown command op %q", cmd.Op)
	}
}

func (o *Owner) applyAddNode(cmd Command) (ApplyResult, error) {
	seed := cmd.Node
	if seed == nil {
		return ApplyResult{}, errors.New("add_node: missing seed")
	}
	if seed.Kind == "" {
		return ApplyResult{}, errors.New("add_node: missing kind")
	}
	for _, dep := range seed.Deps {
		if _, ok := o.graph.Node(dep); !ok {
			return ApplyResult{}, fmt.Errorf("add_node: dependency %d does not exist", dep)
		}
	}

	props := map[string]any{}
	for k, v := range seed.Props {
		props[k] = v
	}
	if seed.Kind == KindIntent {
		if _, ok := props["status"]; !ok {
			props["status"] = StatusTodo
		}
	}
	// Asset vertices are keyed by their anchor value: re-observing the same host
	// or artifact must not fork the graph.
	if seed.Kind == KindAsset {
		if value, ok := props["value"].(string); ok && value != "" {
			if id, found := o.findAsset(value); found {
				return ApplyResult{NodeID: id, Deduped: true}, nil
			}
		}
	}
	id := o.graph.NextNodeID()
	n := &Node{ID: id, Kind: seed.Kind, CreatedAt: time.Now().UTC(), Props: props}
	if err := o.writeEvent(OpAddNode, n); err != nil {
		return ApplyResult{}, err
	}
	if err := o.linkDeps(id, seed.Deps); err != nil {
		return ApplyResult{NodeID: id}, err
	}
	if err := o.linkAnchors(id, seed.Anchors); err != nil {
		return ApplyResult{NodeID: id}, err
	}
	return ApplyResult{NodeID: id}, nil
}

func (o *Owner) applyAddFact(cmd Command) (ApplyResult, error) {
	seed := cmd.Fact
	if seed == nil {
		return ApplyResult{}, errors.New("add_fact: missing seed")
	}
	if seed.Statement == "" {
		return ApplyResult{}, errors.New("add_fact: empty statement")
	}

	reqID := ""
	if seed.Evidence != nil {
		if s, ok := seed.Evidence["request_id"].(string); ok {
			reqID = s
		}
	}
	if id, dup := o.findFact(seed.Statement, reqID); dup {
		// Record the refusal. A silent no-op looks identical to a lost write
		// when someone is auditing the log.
		_ = o.writeEvent(OpSkipped, map[string]any{
			"op":         OpAddFact,
			"reason":     "duplicate fact (same statement + request_id)",
			"statement":  seed.Statement,
			"request_id": reqID,
			"existing":   id,
		})
		return ApplyResult{NodeID: id, Deduped: true}, nil
	}

	props := map[string]any{
		"statement": seed.Statement,
		"tags":      seed.Tags,
	}
	if seed.Evidence != nil {
		props["evidence"] = seed.Evidence
	}
	id := o.graph.NextNodeID()
	n := &Node{ID: id, Kind: KindFact, CreatedAt: time.Now().UTC(), Props: props}
	if err := o.writeEvent(OpAddFact, n); err != nil {
		return ApplyResult{}, err
	}
	if err := o.linkAnchors(id, seed.Anchors); err != nil {
		return ApplyResult{NodeID: id}, err
	}
	return ApplyResult{NodeID: id}, nil
}

// findFact is the idempotency key: statement + request_id.
func (o *Owner) findFact(statement, requestID string) (int64, bool) {
	for _, n := range o.graph.Nodes {
		if n.Kind != KindFact {
			continue
		}
		if n.String("statement") != statement {
			continue
		}
		var ev map[string]any
		if m, ok := n.Prop("evidence").(map[string]any); ok {
			ev = m
		}
		got := ""
		if ev != nil {
			if s, ok := ev["request_id"].(string); ok {
				got = s
			}
		}
		if got == requestID {
			return n.ID, true
		}
	}
	return 0, false
}

func (o *Owner) linkDeps(id int64, deps []int64) error {
	for _, dep := range deps {
		if err := o.writeEvent(OpAddEdge, &Edge{From: id, To: dep, Rel: RelDependsOn}); err != nil {
			return err
		}
	}
	return nil
}

// linkAnchors attaches n to ledger anchors, creating the asset vertex on demand
// so an anchor edge always has a real endpoint in the graph.
func (o *Owner) linkAnchors(id int64, anchors []string) error {
	for _, a := range anchors {
		if a == "" {
			continue
		}
		target, ok := o.findAsset(a)
		if !ok {
			target = o.graph.NextNodeID()
			node := &Node{
				ID:        target,
				Kind:      KindAsset,
				CreatedAt: time.Now().UTC(),
				Props:     map[string]any{"value": a},
			}
			if err := o.writeEvent(OpAddNode, node); err != nil {
				return err
			}
		}
		if err := o.writeEvent(OpAddEdge, &Edge{From: id, To: target, Rel: RelAnchors}); err != nil {
			return err
		}
	}
	return nil
}

func (o *Owner) findAsset(value string) (int64, bool) {
	for _, n := range o.graph.Nodes {
		if n.Kind == KindAsset && n.String("value") == value {
			return n.ID, true
		}
	}
	return 0, false
}

// writeEvent appends one event to disk and folds it into memory. The fold and
// the append use the same encoder, so replay reproduces the in-memory graph
// byte for byte.
func (o *Owner) writeEvent(op string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode %s payload: %w", op, err)
	}
	ev := Event{
		Seq:     o.graph.Seq + 1,
		TS:      time.Now().UTC(),
		Op:      op,
		Payload: raw,
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode %s event: %w", op, err)
	}
	line = append(line, '\n')
	if _, err := o.writer.Write(line); err != nil {
		return fmt.Errorf("append %s: %w", op, err)
	}
	if err := o.writer.Flush(); err != nil {
		return fmt.Errorf("flush %s: %w", op, err)
	}
	return o.graph.Apply(ev)
}
