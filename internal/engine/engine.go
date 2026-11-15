// Package engine is youkai's brain: a bounded event loop over the ledger.
//
// One run = one bounded piece of work. Each iteration derives typed intents from
// the current graph, picks the tier-1 ones whose dependencies are met, runs them
// through a Dispatcher (which is the only place capabilities are reached), writes
// the observations back, and re-derives. It stops at four hard edges:
//
//  1. the next executable intent is tier>=2 -> needs_approval, hand it to a human
//  2. a capability result matches a sensitive pattern -> stop the whole run
//  3. nothing claimable and nothing derivable -> idle
//  4. max_steps reached -> max_steps
//
// The engine never executes tier-2 work, never approves anything, never upgrades
// a finding, and never retries a failed intent.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"youkai/internal/gate"
	"youkai/internal/ledger"
	"youkai/internal/wording"
)

// Store is the slice of the ledger the engine needs. *ledger.Store satisfies it;
// tests use an in-memory fake.
type Store interface {
	Graph(ctx context.Context, engagementID int64) (ledger.GraphView, error)
	EnsureIntent(ctx context.Context, engagementID int64, spec ledger.IntentSpec) (ledger.Intent, bool, error)
	SetIntentStatus(ctx context.Context, engagementID, id int64, status string) error
	// SetIntentDeps retro-fits a chain dependency onto an already-derived step.
	SetIntentDeps(ctx context.Context, engagementID, id int64, deps []int64) error
	AppendTrace(ctx context.Context, engagementID, id int64, line string) error
	// SearchTraces reads back what past steps did: the derivation guard and the
	// planner section both use it.
	SearchTraces(ctx context.Context, engagementID int64, q ledger.TraceQuery) ([]ledger.TraceHit, error)
	Ingest(ctx context.Context, engagementID int64, runID *int64, intentID *int64, obs ledger.Observation) (ledger.IngestResult, error)
	UpsertAsset(ctx context.Context, engagementID int64, seed ledger.AssetSeed) (int64, error)
	FinishRun(ctx context.Context, runID int64, status, stopReason string, steps, derived int) error
	// ActiveMandate is how ADR-005 reaches the engine: a mandate is data in the
	// store (never a flag passed in), so stopping one takes effect on the next run.
	ActiveMandate(ctx context.Context, engagementID int64) (ledger.Mandate, error)
	// MandateUsage counts requests actually sent since the mandate was activated.
	MandateUsage(ctx context.Context, engagement string, since time.Time) (int, error)
	// Whitebox leads: the engine turns open ones into probes and records what the
	// probe found. A lead never becomes evidence here.
	ListHypotheses(ctx context.Context, engagementID int64, state string) ([]ledger.Hypothesis, error)
	SetHypothesisState(ctx context.Context, engagementID, id int64, state, note string) error
}

// Dispatcher runs one capability. The API layer builds it from the web and
// binary registries; the engine never imports them, so adding a capability
// cannot accidentally widen what the engine can reach.
type Dispatcher interface {
	Run(ctx context.Context, engagementID int64, capability string, args map[string]any) (ledger.Observation, error)
}

// AccessPair is one declared ownership relationship: an object the owner has, and
// another identity that must not be able to read it.
type AccessPair struct {
	Owner  string
	Viewer string
	Marker string
	URL    string
}

// PairSource supplies declared ownership (the account layer). Optional: without
// it the engine simply never derives a BOLA comparison.
type PairSource interface {
	BolaPairs(ctx context.Context) ([]AccessPair, error)
}

// Proposer is the optional LLM planner. It proposes; the gate still decides.
type Proposer interface {
	// Propose returns typed intents. Each must carry Provenance (the archived
	// call id); the engine drops proposals without one.
	Propose(ctx context.Context, req ProposeRequest) ([]ledger.IntentSpec, error)
}

// ProposeRequest is what the planner may see: normalised graph state and the
// read-only capability list. Never raw response bodies.
type ProposeRequest struct {
	EngagementID int64
	Engagement   string
	Graph        ledger.GraphView
	Allowed      []string
	RunID        int64
	// PriorWork is what this chain already did, newest last. It lets the model
	// spend its budget on unknown ground instead of re-proposing a check that
	// already ran. It is a projection of our own trace lines: no response bodies,
	// no headers, no credentials.
	PriorWork []ledger.TraceHit
}

// Stop reasons.
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
	DefaultMaxSteps    = 10
	DefaultConcurrency = 3
	defaultMaxLLMRound = 2
)

// Config configures one engine instance.
type Config struct {
	Store        Store
	EngagementID int64
	Engagement   string
	Dispatcher   Dispatcher
	MaxSteps     int
	Concurrency  int
	Proposer     Proposer
	AllowedTools []string
	// PairSource supplies declared ownership pairs for BOLA comparisons.
	PairSource PairSource
	// SeedURLs bootstrap the graph when the engagement scope is empty.
	SeedURLs []string
	// RequireHighAuth gates the ADR-005 mandate path. Off by default: ADR-006
	// replaced "sign a mandate, then act freely inside it" with "one click per
	// risky step", so a mandate is only honoured where a deployment opts back in.
	RequireHighAuth bool
	Now             func() time.Time
}

// StepRecord is one executed intent, as reported to the UI.
type StepRecord struct {
	IntentID   int64         `json:"intent_id"`
	Capability string        `json:"capability"`
	Tier       int           `json:"tier"`
	OK         bool          `json:"ok"`
	Facts      int           `json:"facts"`
	Findings   int           `json:"findings"`
	RequestIDs []string      `json:"request_ids,omitempty"`
	Sensitive  *SensitiveHit `json:"sensitive,omitempty"`
	Err        string        `json:"error,omitempty"`
	DurationMS int64         `json:"duration_ms"`
	Trace      string        `json:"trace,omitempty"`
}

// Pending is one intent waiting at the door, with everything a human needs.
type Pending struct {
	IntentID      int64          `json:"intent_id"`
	Capability    string         `json:"capability"`
	Args          map[string]any `json:"args"`
	Tier          int            `json:"tier"`
	Fingerprint   string         `json:"fingerprint"`
	Reason        string         `json:"reason"`
	ExactRequest  string         `json:"exact_request"`
	MinImpact     string         `json:"min_impact"`
	StopCondition string         `json:"stop_condition"`
	Evidence      []string       `json:"evidence,omitempty"`
	HowToApprove  string         `json:"how_to_approve"`
}

// Report is the outcome of one run.
type Report struct {
	RunID     int64         `json:"run_id"`
	Stop      string        `json:"stop"`
	Reason    string        `json:"reason,omitempty"`
	Steps     []StepRecord  `json:"steps,omitempty"`
	Pending   []Pending     `json:"pending,omitempty"`
	Derived   int           `json:"derived"`
	Sensitive *SensitiveHit `json:"sensitive,omitempty"`
	Provider  string        `json:"exploit_provider"`
}

// Engine runs bounded explorations.
type Engine struct {
	cfg Config
	// priorWork is the trail snapshot for the current derive pass. It is refreshed
	// at the start of every pass and never mutated elsewhere.
	priorWork []ledger.TraceHit
	// orderNote records the ranking of the last batch, for the trace.
	orderNote string
}

// New builds an engine.
func New(cfg Config) (*Engine, error) {
	if cfg.Store == nil {
		return nil, errors.New("engine: store is required")
	}
	if cfg.Dispatcher == nil {
		return nil, errors.New("engine: dispatcher is required")
	}
	if cfg.EngagementID == 0 {
		return nil, errors.New("engine: engagement id is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxSteps <= 0 {
		cfg.MaxSteps = DefaultMaxSteps
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	return &Engine{cfg: cfg}, nil
}

// Run executes one bounded exploration.
func (e *Engine) Run(ctx context.Context, runID int64) (Report, error) {
	rep := Report{RunID: runID, Provider: gate.Provider().Reason()}
	steps := 0
	llmRounds := 0

	finish := func(stop, reason string) (Report, error) {
		rep.Stop = stop
		rep.Reason = reason
		if runID != 0 {
			_ = e.cfg.Store.FinishRun(context.WithoutCancel(ctx), runID, stop, reason, steps, rep.Derived)
		}
		return rep, nil
	}

	for {
		if err := ctx.Err(); err != nil {
			return finish(StopCancelled, err.Error())
		}
		if steps >= e.cfg.MaxSteps {
			return finish(StopMaxSteps, fmt.Sprintf("reached max_steps=%d", e.cfg.MaxSteps))
		}

		derived, err := e.derive(ctx)
		rep.Derived += derived
		if err != nil {
			rep.Stop = StopError
			rep.Reason = "derive: " + err.Error()
			if runID != 0 {
				_ = e.cfg.Store.FinishRun(context.WithoutCancel(ctx), runID, StopError, rep.Reason, steps, rep.Derived)
			}
			return rep, err
		}

		g, err := e.cfg.Store.Graph(ctx, e.cfg.EngagementID)
		if err != nil {
			rep.Stop = StopError
			rep.Reason = "graph: " + err.Error()
			return rep, err
		}

		mc := e.loadMandate(ctx)
		work, blocked := e.choose(g, e.cfg.MaxSteps-steps, mc)
		if mc.usedUp {
			if err := e.cfg.Store.AppendTrace(ctx, e.cfg.EngagementID, 0,
				"mandate budget exhausted: autonomous tier-2 work stops until a human signs a new mandate"); err != nil {
				_ = err
			}
		}

		if len(work) == 0 {
			if len(blocked) > 0 {
				rep.Pending = e.pending(g, blocked)
				if err := e.park(ctx, blocked); err != nil {
					rep.Stop = StopError
					rep.Reason = err.Error()
					return rep, err
				}
				return finish(StopNeedsApproval,
					fmt.Sprintf("%d intent(s) need a human: %s", len(blocked), blocked[0].Capability))
			}
			if e.cfg.Proposer != nil && llmRounds < defaultMaxLLMRound {
				llmRounds++
				n, perr := e.propose(ctx, g, runID)
				if perr != nil {
					rep.Reason = "llm proposer: " + perr.Error()
				}
				if n > 0 {
					rep.Derived += n
					continue
				}
			}
			if rep.Reason == "" {
				rep.Reason = "no claimable intent and no derivable next step"
			}
			return finish(StopIdle, rep.Reason)
		}

		recs := e.execBatch(ctx, work, runID, mc)
		steps += len(recs)
		rep.Steps = append(rep.Steps, recs...)
		for _, rec := range recs {
			if rec.Sensitive != nil {
				rep.Sensitive = rec.Sensitive
				return finish(StopSensitive, fmt.Sprintf(
					"capability %s returned sensitive data (%s); stopping the run for human handling",
					rec.Capability, rec.Sensitive.Name))
			}
		}
	}
}

// choose splits intents into executable-now (tier 1, deps met) and waiting-at-the-door.
func (e *Engine) choose(g ledger.GraphView, budget int, mc mandateCtx) (work, blocked []ledger.Intent) {
	done := map[int64]bool{}
	for _, it := range g.Intents {
		if it.Status == ledger.StatusDone || it.Status == ledger.StatusSkipped {
			done[it.ID] = true
		}
	}
	for _, it := range g.Intents {
		if it.Status != ledger.StatusTodo && it.Status != ledger.StatusNeedsApproval {
			continue
		}
		if !depsMet(it, done) {
			continue
		}
		tier := e.effectiveTier(it)
		switch {
		case tier >= gate.TierDeep:
			// Tier 3 is not reachable by any authorisation, mandate or not.
			blocked = append(blocked, it)
		case tier >= gate.TierProof:
			// A human-signed mandate can pre-authorise a CLASS of tier-2 work for a
			// TARGET it names. Everything else stays behind the one-at-a-time door.
			//
			// needs_approval is included on purpose: a step parked before the mandate
			// was signed should start moving the moment the fence covers it, without
			// asking the operator to re-queue it by hand.
			if (it.Status == ledger.StatusTodo || it.Status == ledger.StatusNeedsApproval) && mc.covers(it) {
				work = append(work, it)
				continue
			}
			blocked = append(blocked, it)
		case it.Status == ledger.StatusTodo && tier.AutonomousOK():
			work = append(work, it)
		}
	}
	// v0.17: rank by evidence, deterministically. The order decides what the budget
	// is spent on; it never decides what is allowed.
	scored := e.orderWork(work)
	ordered := make([]ledger.Intent, 0, len(scored))
	for _, s := range scored {
		ordered = append(ordered, s.Intent)
	}
	work = ordered
	if line := explainOrder(scored); line != "" && len(work) > 1 {
		e.orderNote = line
	}
	if budget > 0 && len(work) > budget {
		work = work[:budget]
	}
	return work, blocked
}

func depsMet(it ledger.Intent, done map[int64]bool) bool {
	for _, d := range it.Deps {
		if !done[d] {
			return false // fail closed
		}
	}
	return true
}

// effectiveTier is max(what the gate says now, what the intent claims). An intent
// that declares itself proof-grade stays proof-grade even if the gate would let a
// bare call through.
func (e *Engine) effectiveTier(it ledger.Intent) gate.Tier {
	byGate := gate.Classify(it.Capability, it.Args)
	if declared := gate.Tier(it.Tier); declared > byGate {
		return declared
	}
	return byGate
}

// park marks blocked intents as needing approval, without executing anything.
func (e *Engine) park(ctx context.Context, blocked []ledger.Intent) error {
	for _, it := range blocked {
		if it.Status == ledger.StatusNeedsApproval {
			continue
		}
		if err := e.cfg.Store.SetIntentStatus(ctx, e.cfg.EngagementID, it.ID, ledger.StatusNeedsApproval); err != nil {
			return err
		}
		line := "parked at needs_approval by the engine: " +
			gate.Explain(it.Capability, it.Args).Reason +
			"; youkai does not approve or execute tier>=2"
		_ = e.cfg.Store.AppendTrace(ctx, e.cfg.EngagementID, it.ID, line)
	}
	return nil
}

// pending renders the door for a human.
func (e *Engine) pending(g ledger.GraphView, blocked []ledger.Intent) []Pending {
	out := make([]Pending, 0, len(blocked))
	for _, it := range blocked {
		dec := gate.Explain(it.Capability, it.Args)
		out = append(out, Pending{
			IntentID:      it.ID,
			Capability:    it.Capability,
			Args:          it.Args,
			Tier:          int(e.effectiveTier(it)),
			Fingerprint:   it.Fingerprint,
			Reason:        dec.Reason,
			ExactRequest:  wording.Describe(it.Capability, it.Args),
			MinImpact:     wording.MinImpact(it.Capability),
			StopCondition: wording.StopCondition(it.Capability),
			Evidence:      relatedEvidence(g, it),
			HowToApprove: "operator decision in the approval workbench: an explicit approval " +
				"(operator + basis) plus, for remote actions, a Fairy-style high-auth record. " +
				"One step, then stop.",
		})
	}
	return out
}

// relatedEvidence lists the facts anchored near an intent.
func relatedEvidence(g ledger.GraphView, it ledger.Intent) []string {
	anchors := map[string]bool{}
	for _, e := range g.Edges {
		if e.FromKind == "intent" && e.FromID == it.ID && e.ToKind == "asset" && e.Rel == ledger.RelAnchors {
			for _, a := range g.Assets {
				if a.ID == e.ToID {
					anchors[a.Value] = true
				}
			}
		}
	}
	if len(anchors) == 0 {
		return nil
	}
	var out []string
	for _, f := range g.Facts {
		for _, e := range g.Edges {
			if e.FromKind == "fact" && e.FromID == f.ID && e.ToKind == "asset" && e.Rel == ledger.RelAnchors {
				for _, a := range g.Assets {
					if a.ID == e.ToID && anchors[a.Value] {
						ev := ""
						if id, ok := f.Evidence["request_id"].(string); ok && id != "" {
							ev = " request_id=" + id
						}
						out = append(out, fmt.Sprintf("#%d %s%s", f.ID, f.Statement, ev))
					}
				}
			}
		}
	}
	return out
}

// execBatch claims and runs tier-1 intents.
func (e *Engine) execBatch(ctx context.Context, batch []ledger.Intent, runID int64, mc mandateCtx) []StepRecord {
	type job struct {
		intent ledger.Intent
		err    error
	}
	jobs := make([]job, 0, len(batch))
	for _, it := range batch {
		// Claim first: the status flip is what guarantees one execution.
		cerr := e.cfg.Store.SetIntentStatus(ctx, e.cfg.EngagementID, it.ID, ledger.StatusActive)
		jobs = append(jobs, job{intent: it, err: cerr})
	}

	recs := make([]StepRecord, len(jobs))
	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup
	for i := range jobs {
		if jobs[i].err != nil {
			recs[i] = StepRecord{
				IntentID:   jobs[i].intent.ID,
				Capability: jobs[i].intent.Capability,
				Tier:       int(e.effectiveTier(jobs[i].intent)),
				Err:        "claim failed: " + jobs[i].err.Error(),
			}
			continue
		}
		wg.Add(1)
		go func(i int, it ledger.Intent) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer func() {
				if p := recover(); p != nil {
					recs[i] = StepRecord{
						IntentID: it.ID, Capability: it.Capability,
						Tier: int(e.effectiveTier(it)),
						Err:  fmt.Sprintf("capability panic: %v", p),
					}
					_ = e.cfg.Store.AppendTrace(context.WithoutCancel(ctx), e.cfg.EngagementID, it.ID,
						fmt.Sprintf("capability panic: %v (no retry; intent left active)", p))
				}
			}()
			recs[i] = e.execOne(ctx, it, runID, !tierAutonomous(e, it) && mc.covers(it))
		}(i, jobs[i].intent)
	}
	wg.Wait()
	return recs
}

// execOne runs exactly one claimed intent.
func (e *Engine) execOne(ctx context.Context, it ledger.Intent, runID int64, mandated bool) StepRecord {
	started := e.cfg.Now()
	rec := StepRecord{IntentID: it.ID, Capability: it.Capability, Tier: int(e.effectiveTier(it))}
	dec := gate.Explain(it.Capability, it.Args)

	// Second wall check. choose() already filtered; a worker that trusts its
	// caller is not a wall.
	//
	// A mandated step is the one exception, and it is narrow: the gate still says
	// tier 2, so the mandate is re-read from the store right here. A stop or expiry
	// that landed between the round and this step is therefore caught before the
	// request, not after it.
	if !dec.Allowed() && !mandated {
		_ = e.cfg.Store.SetIntentStatus(ctx, e.cfg.EngagementID, it.ID, ledger.StatusNeedsApproval)
		msg := "gate refused at dispatch: " + dec.Reason
		_ = e.cfg.Store.AppendTrace(ctx, e.cfg.EngagementID, it.ID, msg)
		rec.Err = msg
		rec.Trace = msg
		return rec
	}
	if mandated && !e.loadMandate(ctx).covers(it) {
		_ = e.cfg.Store.SetIntentStatus(ctx, e.cfg.EngagementID, it.ID, ledger.StatusNeedsApproval)
		msg := "mandate no longer covers this step (stopped, expired, or out of budget): parked for a human"
		_ = e.cfg.Store.AppendTrace(ctx, e.cfg.EngagementID, it.ID, msg)
		rec.Err = msg
		rec.Trace = msg
		return rec
	}

	obs, err := e.cfg.Dispatcher.Run(ctx, e.cfg.EngagementID, it.Capability, it.Args)
	rec.DurationMS = e.cfg.Now().Sub(started).Milliseconds()
	if err != nil {
		return e.fail(ctx, it, rec, "capability failed: "+err.Error())
	}

	intentID := it.ID
	res, ierr := e.cfg.Store.Ingest(ctx, e.cfg.EngagementID, &runID, &intentID, obs)
	if ierr != nil {
		return e.fail(ctx, it, rec, "ingest: "+ierr.Error())
	}
	rec.Facts = res.NewFacts
	rec.Findings = len(res.FindingIDs)
	rec.RequestIDs = obs.RequestIDs

	// Sensitive-data check scans the observation's textual surface - the parts we
	// were about to keep - not the response body (which never reaches here).
	hit, sensitive := ScanSensitive(observationText(obs))

	trace := fmt.Sprintf("capability=%s ok=true tier=%d facts=%d findings=%d",
		it.Capability, rec.Tier, rec.Facts, rec.Findings)
	if mandated {
		// The report and the conversation both need to say HOW this ran: under a
		// human-signed mandate, not under a per-step approval.
		trace += " under=mandate"
	}
	if len(obs.RequestIDs) > 0 {
		trace += " request_ids=" + joinLimited(obs.RequestIDs, 6)
	}
	if sensitive {
		trace += " SENSITIVE=" + hit.Name
	}
	rec.Trace = trace

	// A probe derived from a whitebox lead settles that lead: hit -> candidate,
	// miss -> unconfirmed. The lead itself never becomes a finding.
	if id := hypothesisIDOf(it.Args); id > 0 {
		e.ConfirmHypothesis(ctx, id, rec.Findings, rec.RequestIDs)
	}

	if err := e.cfg.Store.SetIntentStatus(ctx, e.cfg.EngagementID, it.ID, ledger.StatusDone); err != nil {
		return e.fail(ctx, it, rec, "mark done: "+err.Error())
	}
	_ = e.cfg.Store.AppendTrace(ctx, e.cfg.EngagementID, it.ID, trace)

	rec.OK = true
	if sensitive {
		rec.Sensitive = &hit
	}
	return rec
}

// fail records a failed step. The intent stays active so this engine never
// silently retries it; a human can requeue it deliberately.
func (e *Engine) fail(ctx context.Context, it ledger.Intent, rec StepRecord, msg string) StepRecord {
	rec.OK = false
	rec.Err = msg
	rec.Trace = msg
	// A failed step must not stay "active": nothing is running it any more, the
	// workbench does not show it, and the fingerprint dedupe stops it from being
	// re-derived - one transient failure would wedge the chain for good. "blocked"
	// keeps it visible and out of the claim path until a human looks.
	_ = e.cfg.Store.SetIntentStatus(ctx, e.cfg.EngagementID, it.ID, ledger.StatusBlocked)
	_ = e.cfg.Store.AppendTrace(ctx, e.cfg.EngagementID, it.ID,
		msg+" (no retry; marked blocked, not re-derived)")
	return rec
}

// propose asks the LLM planner for read-only next steps.
func (e *Engine) propose(ctx context.Context, g ledger.GraphView, runID int64) (int, error) {
	specs, err := e.cfg.Proposer.Propose(ctx, ProposeRequest{
		EngagementID: e.cfg.EngagementID,
		Engagement:   e.cfg.Engagement,
		Graph:        g,
		Allowed:      e.cfg.AllowedTools,
		RunID:        runID,
		PriorWork:    e.priorForPrompt(),
	})
	if err != nil {
		return 0, err
	}
	added := 0
	for _, spec := range specs {
		if spec.Provenance == "" {
			continue // unreplayable proposals are inadmissible
		}
		spec.Inferred = true
		if _, created, err := e.cfg.Store.EnsureIntent(ctx, e.cfg.EngagementID, spec); err != nil {
			return added, err
		} else if created {
			added++
		}
	}
	return added, nil
}

// observationText is the textual surface the sensitive detector scans.
//
// It includes evidence VALUES because that is where a capability records a short
// preview of what it saw (a body snippet, a header value). Blindly scanning the
// raw response body would be both too broad (youkai never keeps it) and too late.
func observationText(obs ledger.Observation) string {
	var b []byte
	appendEv := func(ev map[string]any) {
		for _, v := range ev {
			switch t := v.(type) {
			case string:
				b = append(b, t...)
				b = append(b, '\n')
			case []any:
				for _, e := range t {
					if s, ok := e.(string); ok {
						b = append(b, s...)
						b = append(b, '\n')
					}
				}
			}
		}
	}
	for _, f := range obs.Facts {
		b = append(b, f.Statement...)
		b = append(b, '\n')
		appendEv(f.Evidence)
	}
	for _, f := range obs.Findings {
		b = append(b, f.Title...)
		b = append(b, '\n')
		b = append(b, f.Detail...)
		b = append(b, '\n')
		appendEv(f.Evidence)
	}
	return string(b)
}

func joinLimited(items []string, max int) string {
	out := ""
	for i, s := range items {
		if i >= max {
			out += ",…"
			break
		}
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// priorForPrompt returns a bounded trail snapshot for the planner prompt.
func (e *Engine) priorForPrompt() []ledger.TraceHit {
	if len(e.priorWork) == 0 {
		return nil
	}
	const maxPrior = 40
	if len(e.priorWork) > maxPrior {
		return e.priorWork[len(e.priorWork)-maxPrior:]
	}
	return e.priorWork
}

// tierAutonomous reports whether the gate would let this intent run on its own.
func tierAutonomous(e *Engine, it ledger.Intent) bool {
	return e.effectiveTier(it).AutonomousOK()
}

// hypothesisIDOf reads the lead id a probe was derived for (0 when none).
func hypothesisIDOf(args map[string]any) int64 {
	switch v := args["hypothesis_id"].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}
