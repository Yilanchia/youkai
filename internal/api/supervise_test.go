package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"youkai/internal/ledger"
)

// TestSupervisedRunCrossesTheStepCapItself is the core of v0.22: a run that hits
// the per-round step cap must keep going by itself while there is read-only work
// left, instead of stopping and asking the operator to press "continue".
//
// Fifteen queued tier-1 steps, a per-round cap of 10: one run, fifteen executed,
// and it ends because there is nothing left - not because it ran out of rounds.
func TestSupervisedRunCrossesTheStepCapItself(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	for i := 0; i < 15; i++ {
		_, _, err := f.store.EnsureIntent(ctx, f.eng.ID, ledger.IntentSpec{
			Capability: "headers",
			Args:       map[string]any{"url": fmt.Sprintf("http://127.0.0.1:18080/p%d", i)},
			Tier:       1,
			Rationale:  fmt.Sprintf("supervision fixture step %d", i),
		})
		if err != nil {
			t.Fatalf("seed intent %d: %v", i, err)
		}
	}

	code, body := f.do(t, http.MethodPost, fmt.Sprintf("/api/engagements/%d/runs", f.eng.ID),
		map[string]any{"max_steps": 10}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("start run = %d %v", code, body)
	}

	var run ledger.Run
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		runs, err := f.store.ListRuns(ctx, f.eng.ID, 5)
		if err != nil {
			t.Fatalf("list runs: %v", err)
		}
		if len(runs) > 0 && runs[0].Status != "running" {
			run = runs[0]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if run.ID == 0 {
		t.Fatal("the run never finished")
	}
	if run.Steps < 15 {
		t.Fatalf("run did %d steps (status=%s reason=%q), want 15: the supervised loop stopped at the per-round cap",
			run.Steps, run.Status, run.StopReason)
	}
	if run.Status != "idle" {
		t.Fatalf("status = %q, want idle (it should keep going until nothing is left)", run.Status)
	}
}

// TestSupervisedRunStopsAtATierTwoStep: the same loop must NOT cross a real stop.
func TestSupervisedRunStopsAtATierTwoStep(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, _, err := f.store.EnsureIntent(ctx, f.eng.ID, ledger.IntentSpec{
			Capability: "headers",
			Args:       map[string]any{"url": fmt.Sprintf("http://127.0.0.1:18080/s%d", i)},
			Tier:       1, Rationale: "read-only fixture step",
		}); err != nil {
			t.Fatalf("seed tier-1: %v", err)
		}
	}
	if _, _, err := f.store.EnsureIntent(ctx, f.eng.ID, ledger.IntentSpec{
		Capability: "param",
		Args:       map[string]any{"url": "http://127.0.0.1:18080/sql?q=1", "param": "q"},
		Tier:       2, RequiresApproval: true, Rationale: "tier-2 fixture step",
	}); err != nil {
		t.Fatalf("seed tier-2: %v", err)
	}

	if code, body := f.do(t, http.MethodPost, fmt.Sprintf("/api/engagements/%d/runs", f.eng.ID),
		map[string]any{"max_steps": 10}, nil); code != http.StatusAccepted {
		t.Fatalf("start run = %d %v", code, body)
	}

	deadline := time.Now().Add(20 * time.Second)
	var run ledger.Run
	for time.Now().Before(deadline) {
		runs, err := f.store.ListRuns(ctx, f.eng.ID, 5)
		if err != nil {
			t.Fatalf("list runs: %v", err)
		}
		if len(runs) > 0 && runs[0].Status != "running" {
			run = runs[0]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if run.ID == 0 {
		t.Fatal("the run never finished")
	}
	if run.Status != "needs_approval" {
		t.Fatalf("status = %q, want needs_approval: supervision must not cross a tier-2 stop", run.Status)
	}
	// And the tier-2 step is still waiting, not executed.
	intents, err := f.store.ListIntents(ctx, f.eng.ID)
	if err != nil {
		t.Fatalf("list intents: %v", err)
	}
	for _, it := range intents {
		if it.Capability == "param" && it.Status != ledger.StatusNeedsApproval {
			t.Fatalf("the tier-2 step ran without approval: %+v", it)
		}
	}
}

// TestCancelStopsASupervisedRun: the operator can always take the wheel back.
func TestCancelStopsASupervisedRun(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	// Enough work that it cannot possibly finish before the cancel lands.
	for i := 0; i < 40; i++ {
		if _, _, err := f.store.EnsureIntent(ctx, f.eng.ID, ledger.IntentSpec{
			Capability: "headers",
			Args:       map[string]any{"url": fmt.Sprintf("http://127.0.0.1:18080/c%d", i)},
			Tier:       1, Rationale: "slow fixture step",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	code, body := f.do(t, http.MethodPost, fmt.Sprintf("/api/engagements/%d/runs", f.eng.ID),
		map[string]any{"max_steps": 5}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("start = %d %v", code, body)
	}
	runID := int64(body["run_id"].(float64))
	// Cancel almost immediately.
	time.Sleep(80 * time.Millisecond)
	if code, body := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/runs/%d/cancel", f.eng.ID, runID), map[string]any{}, nil); code != http.StatusOK {
		t.Fatalf("cancel = %d %v", code, body)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		runs, err := f.store.ListRuns(ctx, f.eng.ID, 5)
		if err != nil {
			t.Fatalf("list runs: %v", err)
		}
		if len(runs) > 0 && runs[0].Status != "running" {
			if runs[0].Steps >= 40 {
				t.Fatalf("cancel did not stop the session: it ran %d steps", runs[0].Steps)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the run never stopped after cancel")
}

// TestSupervisedRunEndsWithATurn: a supervised run must not just stop - it says
// what happened and what the options are, in the conversation, with or without a
// model configured.
func TestSupervisedRunEndsWithATurn(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, _, err := f.store.EnsureIntent(ctx, f.eng.ID, ledger.IntentSpec{
			Capability: "headers",
			Args:       map[string]any{"url": fmt.Sprintf("http://127.0.0.1:18080/t%d", i)},
			Tier:       1, Rationale: "summary fixture step",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if code, body := f.do(t, http.MethodPost, fmt.Sprintf("/api/engagements/%d/runs", f.eng.ID),
		map[string]any{"max_steps": 5}, nil); code != http.StatusAccepted {
		t.Fatalf("start = %d %v", code, body)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		runs, err := f.store.ListRuns(ctx, f.eng.ID, 5)
		if err != nil {
			t.Fatalf("list runs: %v", err)
		}
		if len(runs) > 0 && runs[0].Status != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	msgs, err := f.store.ChatHistory(ctx, f.eng.ID, 50)
	if err != nil {
		t.Fatalf("chat history: %v", err)
	}
	var summary string
	for _, m := range msgs {
		if m.Role == "assistant" {
			summary = m.Content
		}
	}
	if summary == "" {
		t.Fatal("the run ended without a closing message")
	}
	if !strings.Contains(summary, "候选") {
		t.Fatalf("the closing message does not report what was found: %q", summary)
	}
	// The template must never promise to act on its own.
	for _, banned := range []string{"我已经继续", "自动继续", "我已批准"} {
		if strings.Contains(summary, banned) {
			t.Fatalf("the summary claims an unauthorised action: %q", summary)
		}
	}
}
