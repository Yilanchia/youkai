// Package loop is the deterministic heart of youkai: a bounded event loop that
// turns ledger facts and graph state into typed intents, executes the read-only
// ones through a hand, writes observations back, and STOPS at the door of
// anything proof-grade.
//
// The loop is deliberately dumb about capability: it asks gate.Classify about
// every action at dispatch time, and it refuses to execute anything above tier 1
// even when someone has set approved=true. Approval is a human path through
// Fairy's high-auth, not a boolean this loop honours.
package loop

import (
	"context"
	"fmt"
	"sync"
	"time"

	"youkai/internal/gate"
	"youkai/internal/graph"
	"youkai/internal/mcp"
	"youkai/internal/wording"
)

// Hands is the brain's view of its two hands. The real implementation is
// internal/hands; tests substitute a fake so the loop's safety properties can be
// checked without a live target.
type Hands interface {
	// HandFor routes a tool name to the hand that owns it.
	HandFor(tool string) (string, error)
	// Call invokes one tool on one hand.
	Call(ctx context.Context, hand, tool string, args map[string]any) (mcp.ToolResult, error)
}

// ProposeRequest is what an LLM planner is allowed to see: normalised graph state
// and a whitelist. Never raw response bodies.
type ProposeRequest struct {
	Project      string
	Graph        *graph.Graph
	AllowedTools []string
}

// Proposer is the optional LLM planner (module 4). It proposes, it never decides.
type Proposer interface {
	Propose(ctx context.Context, req ProposeRequest) ([]IntentSpec, error)
}

// Stop reasons. These strings end up in run reports.
const (
	StopIdle          = "idle"
	StopNeedsApproval = "needs_approval"
	StopSensitive     = "sensitive_stop"
	StopMaxSteps      = "max_steps"
	StopCancelled     = "cancelled"
	StopError         = "error"
)

// Defaults.
const (
	defaultMaxSteps    = 10
	defaultConcurrency = 3
	defaultMaxLLMRound = 3
)

// Config is the runner's tuning and engagement context.
type Config struct {
	// Project is the Fairy engagement directory (passed to every Fairy call).
	Project string
	// SeedHosts bootstraps the graph when the ledger is empty. They do not
	// bypass authorisation: Fairy still enforces its scope passport.
	SeedHosts []string
	// MaxSteps bounds one run. Default 10.
	MaxSteps int
	// Concurrency is the worker pool size. Default 3.
	Concurrency int
	// Debounce coalesces "graph changed" signals between ticks. Default 0 for a
	// synchronous run; the watcher uses 200ms.
	Debounce time.Duration
	// MaxLLMRounds bounds how many times the LLM fallback may fire in one run.
	MaxLLMRounds int
	// Proposer is optional. Without it the loop is fully deterministic.
	Proposer Proposer
	// AllowedTools is the read-only whitelist shown to the LLM.
	AllowedTools []string
}

// StepRecord is one executed intent, as it appears in the report.
type StepRecord struct {
	IntentID  int64         `json:"intent_id"`
	Action    string        `json:"action"`
	Hand      string        `json:"hand,omitempty"`
	Tier      int           `json:"tier"`
	OK        bool          `json:"ok"`
	Facts     int           `json:"facts"`
	Findings  int           `json:"findings"`
	RequestID string        `json:"request_id,omitempty"`
	AuditPath string        `json:"audit_path,omitempty"`
	RunID     string        `json:"run_id,omitempty"`
	Sensitive *SensitiveHit `json:"sensitive,omitempty"`
	Err       string        `json:"error,omitempty"`
	Decision  string        `json:"decision,omitempty"`
	Trace     string        `json:"trace,omitempty"`
}

// Pending is one intent waiting at the door, with the evidence a human needs to
// decide. youkai does not approve it; it explains it.
type Pending struct {
	IntentID      int64          `json:"intent_id"`
	Action        string         `json:"action"`
	Args          map[string]any `json:"args"`
	Tier          int            `json:"tier"`
	Reason        string         `json:"reason"`
	Anchors       []string       `json:"anchors,omitempty"`
	ExactRequest  string         `json:"exact_request"`
	MinImpact     string         `json:"min_impact"`
	StopCondition string         `json:"stop_condition"`
	Evidence      []string       `json:"evidence,omitempty"`
	// HowToApprove is the exact human path; youkai has no way to take it.
	HowToApprove string `json:"how_to_approve"`
}

// Report is the result of one bounded run.
type Report struct {
	Stop            string        `json:"stop"`
	Reason          string        `json:"reason,omitempty"`
	Steps           []StepRecord  `json:"steps,omitempty"`
	Pending         []Pending     `json:"pending,omitempty"`
	Derived         int           `json:"derived_intents"`
	Sensitive       *SensitiveHit `json:"sensitive,omitempty"`
	ExploitProvider string        `json:"exploit_provider"`
}

// OK reports whether the run ended without an infrastructure error.
func (r Report) OK() bool { return r.Stop != StopError }

// Runner drives one exploration graph.
type Runner struct {
	cfg   Config
	owner *graph.Owner
	hands Hands
}

// New builds a runner.
func New(cfg Config, owner *graph.Owner, hands Hands) (*Runner, error) {
	if owner == nil {
		return nil, fmt.Errorf("loop: owner is required")
	}
	if hands == nil {
		return nil, fmt.Errorf("loop: hands are required")
	}
	return &Runner{cfg: cfg, owner: owner, hands: hands}, nil
}

func (r *Runner) maxSteps() int {
	if r.cfg.MaxSteps > 0 {
		return r.cfg.MaxSteps
	}
	return defaultMaxSteps
}

func (r *Runner) concurrency() int {
	if r.cfg.Concurrency > 0 {
		return r.cfg.Concurrency
	}
	return defaultConcurrency
}

func (r *Runner) maxLLMRounds() int {
	if r.cfg.MaxLLMRounds > 0 {
		return r.cfg.MaxLLMRounds
	}
	return defaultMaxLLMRound
}

// Run executes the bounded loop until a hard stop condition.
//
// Hard stops (the loop never crosses these):
//  1. the next executable intent is tier>=2 (or already parked at needs_approval)
//  2. a worker result carries a sensitive-data hit
//  3. nothing left to claim and no new intent can be derived -> idle
//  4. max_steps reached
func (r *Runner) Run(ctx context.Context) (Report, error) {
	rep := Report{ExploitProvider: gate.Provider().Reason()}
	steps := 0
	llmRounds := 0

	for {
		if err := ctx.Err(); err != nil {
			rep.Stop = StopCancelled
			rep.Reason = err.Error()
			return rep, nil
		}
		if steps >= r.maxSteps() {
			rep.Stop = StopMaxSteps
			rep.Reason = fmt.Sprintf("reached max_steps=%d", r.maxSteps())
			return rep, nil
		}

		added, err := r.tick(ctx)
		rep.Derived += added
		if err != nil {
			rep.Stop = StopError
			rep.Reason = "planner tick: " + err.Error()
			return rep, err
		}

		g := r.owner.Snapshot()
		work, blocked := r.choose(g, r.maxSteps()-steps)

		if len(work) == 0 {
			if len(blocked) > 0 {
				rep.Pending = r.pending(g, blocked)
				if err := r.park(blocked); err != nil {
					rep.Stop = StopError
					rep.Reason = err.Error()
					return rep, err
				}
				rep.Stop = StopNeedsApproval
				rep.Reason = fmt.Sprintf("%d intent(s) need a human: %s", len(blocked), blocked[0].String("action"))
				return rep, nil
			}

			// Deterministic rules are exhausted; the LLM may suggest read-only
			// next steps. Its output goes through the same gate.
			if r.cfg.Proposer != nil && llmRounds < r.maxLLMRounds() {
				llmRounds++
				n, perr := r.propose(ctx)
				if perr != nil {
					// The LLM is a supplement, not a dependency: a failure is a
					// note, not a crash.
					rep.Reason = "llm proposer: " + perr.Error()
				}
				if n > 0 {
					rep.Derived += n
					continue
				}
			}
			rep.Stop = StopIdle
			if rep.Reason == "" {
				rep.Reason = "no claimable intent and no derivable next step"
			}
			return rep, nil
		}

		recs := r.execBatch(ctx, work)
		steps += len(recs)
		rep.Steps = append(rep.Steps, recs...)

		for _, rec := range recs {
			if rec.Sensitive != nil {
				rep.Stop = StopSensitive
				rep.Sensitive = rec.Sensitive
				rep.Reason = fmt.Sprintf("worker result on %s matched sensitive pattern %q; stopping the whole round for human handling",
					rec.Action, rec.Sensitive.Name)
				return rep, nil
			}
		}
		r.settle(ctx)
	}
}

// settle coalesces the burst of "graph changed" signals one batch produces.
func (r *Runner) settle(ctx context.Context) {
	if r.cfg.Debounce <= 0 {
		return
	}
	t := time.NewTimer(r.cfg.Debounce)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// choose splits intents into "executable now" (tier 1, deps satisfied) and
// "waiting at the door" (tier >= 2, deps satisfied, or already parked).
func (r *Runner) choose(g *graph.Graph, budget int) (work, blocked []*graph.Node) {
	for _, n := range g.OfKind(graph.KindIntent) {
		st := n.Status()
		if st != graph.StatusTodo && st != graph.StatusNeedsApproval {
			continue
		}
		if !depsSatisfied(g, n) {
			continue
		}
		switch tier := r.effectiveTier(n); {
		case tier >= gate.TierProof:
			blocked = append(blocked, n)
		case st == graph.StatusTodo && tier.AutonomousOK():
			work = append(work, n)
		}
	}
	if budget > 0 && len(work) > budget {
		work = work[:budget]
	}
	return work, blocked
}

// effectiveTier is max(what the gate says, what the intent claims). An intent
// that declares itself proof-grade stays proof-grade even if the gate would let a
// bare version of the call through.
func (r *Runner) effectiveTier(n *graph.Node) gate.Tier {
	byGate := gate.Classify(n.String("action"), n.Map("args"))
	if declared := gate.Tier(n.Int("tier")); declared > byGate {
		return declared
	}
	return byGate
}

func depsSatisfied(g *graph.Graph, n *graph.Node) bool {
	for _, dep := range g.Deps(n.ID) {
		d, ok := g.Node(dep)
		if !ok {
			return false // fail closed
		}
		switch d.Status() {
		case graph.StatusDone, graph.StatusSkipped:
		default:
			return false
		}
	}
	return true
}

// park marks blocked intents as needing approval, without executing anything.
func (r *Runner) park(blocked []*graph.Node) error {
	for _, n := range blocked {
		if n.Status() == graph.StatusNeedsApproval {
			continue
		}
		if _, err := r.owner.Apply(graph.CmdSetStatus(n.ID, graph.StatusNeedsApproval)); err != nil {
			return err
		}
		trace := "parked at needs_approval by the loop: " +
			gate.Explain(n.String("action"), n.Map("args")).Reason +
			"; youkai does not approve or execute tier>=2"
		if _, err := r.owner.Apply(graph.CmdAddTrace(n.ID, trace)); err != nil {
			return err
		}
	}
	return nil
}

// pending renders the door for a human.
func (r *Runner) pending(g *graph.Graph, blocked []*graph.Node) []Pending {
	out := make([]Pending, 0, len(blocked))
	for _, n := range blocked {
		action := n.String("action")
		args := n.Map("args")
		dec := gate.Explain(action, args)
		p := Pending{
			IntentID:      n.ID,
			Action:        action,
			Args:          args,
			Tier:          int(r.effectiveTier(n)),
			Reason:        dec.Reason,
			Anchors:       g.Anchors(n.ID),
			ExactRequest:  wording.Describe(action, args),
			MinImpact:     wording.MinImpact(action),
			StopCondition: wording.StopCondition(action),
			HowToApprove: "human path only: run it through Fairy with high-auth + a single confirm, " +
				"then ingest the result back into this graph (fairy_ingest / youkai intent done)",
			Evidence: relatedEvidence(g, n),
		}
		out = append(out, p)
	}
	return out
}

// relatedEvidence lists the fact statements anchored near an intent, so the human
// sees what the brain already knows before approving.
func relatedEvidence(g *graph.Graph, n *graph.Node) []string {
	var out []string
	anchors := map[string]bool{}
	for _, a := range g.Anchors(n.ID) {
		anchors[a] = true
	}
	for _, f := range g.OfKind(graph.KindFact) {
		if len(anchors) == 0 {
			break
		}
		for _, a := range g.Anchors(f.ID) {
			if anchors[a] {
				out = append(out, fmt.Sprintf("#%d %s", f.ID, f.String("statement")))
				break
			}
		}
	}
	return out
}

// execBatch claims and runs up to the pool size of tier-1 intents.
func (r *Runner) execBatch(ctx context.Context, batch []*graph.Node) []StepRecord {
	type job struct {
		n   *graph.Node
		err error
	}
	jobs := make([]job, 0, len(batch))
	for _, n := range batch {
		_, err := r.owner.Apply(graph.CmdSetStatus(n.ID, graph.StatusActive))
		jobs = append(jobs, job{n: n, err: err})
	}

	recs := make([]StepRecord, len(jobs))
	sem := make(chan struct{}, r.concurrency())
	var wg sync.WaitGroup
	for i := range jobs {
		if jobs[i].err != nil {
			// Could not claim: record it and do not execute.
			recs[i] = StepRecord{
				IntentID: jobs[i].n.ID,
				Action:   jobs[i].n.String("action"),
				Tier:     int(r.effectiveTier(jobs[i].n)),
				Err:      "claim failed: " + jobs[i].err.Error(),
			}
			continue
		}
		wg.Add(1)
		go func(i int, n *graph.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// A malformed hand result must not take the brain down; record the
			// panic as a failed step instead (the intent stays active, no retry).
			defer func() {
				if p := recover(); p != nil {
					recs[i] = StepRecord{
						IntentID: n.ID,
						Action:   n.String("action"),
						Tier:     int(r.effectiveTier(n)),
						Err:      fmt.Sprintf("worker panic: %v", p),
						Trace:    fmt.Sprintf("worker panic: %v", p),
					}
					_, _ = r.owner.Apply(graph.CmdAddTrace(n.ID, fmt.Sprintf(
						"worker panic: %v (no retry; intent left active)", p)))
				}
			}()
			recs[i] = r.execOne(ctx, n)
		}(i, jobs[i].n)
	}
	wg.Wait()
	return recs
}

// propose asks the LLM planner for read-only next steps and writes them as
// inferred intents. No archive, no intent: an unreplayable proposal is refused.
func (r *Runner) propose(ctx context.Context) (int, error) {
	g := r.owner.Snapshot()
	specs, err := r.cfg.Proposer.Propose(ctx, ProposeRequest{
		Project:      r.cfg.Project,
		Graph:        g,
		AllowedTools: r.cfg.AllowedTools,
	})
	if err != nil {
		return 0, err
	}
	added := 0
	for _, spec := range specs {
		if spec.Provenance == "" {
			// Without the archived call, the proposal cannot be replayed later.
			continue
		}
		spec.Inferred = true
		if _, created, err := r.addIntent(spec); err != nil {
			return added, err
		} else if created {
			added++
		}
	}
	return added, nil
}

// callHand invokes a tool and injects the engagement project for Fairy.
func (r *Runner) callHand(ctx context.Context, hand, tool string, args map[string]any) (mcp.ToolResult, error) {
	return r.hands.Call(ctx, hand, tool, r.callArgs(hand, args))
}

func (r *Runner) callArgs(hand string, args map[string]any) map[string]any {
	out := make(map[string]any, len(args)+1)
	for k, v := range args {
		out[k] = v
	}
	if hand == HandFairy && r.cfg.Project != "" {
		if _, ok := out["project"]; !ok {
			out["project"] = r.cfg.Project
		}
	}
	return out
}

// HandFairy is the web hand's logical name.
const HandFairy = "fairy"

// HandVerdex is the binary hand's logical name.
const HandVerdex = "verdex"
