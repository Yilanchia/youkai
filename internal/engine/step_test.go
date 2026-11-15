package engine

import (
	"context"
	"strings"
	"testing"
)

// TestStepsAreNarratedInOrder is the point of v0.21: a run must produce a readable
// stream of what it did - derive, exec, reflect, stop - not silence until the end.
func TestStepsAreNarratedInOrder(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	var events []StepEvent
	eng := newEngine(t, f, &fakeDispatcher{}, Config{
		MaxSteps: 4,
		OnStep:   func(ev StepEvent) { events = append(events, ev) },
	})
	if _, err := eng.Run(context.Background(), 7); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("only %d events, want a stream", len(events))
	}
	// Sequence numbers must be monotonic and every event must be stamped.
	last := 0
	phases := map[string]bool{}
	for _, ev := range events {
		if ev.Seq <= last {
			t.Fatalf("seq %d did not advance (last %d)", ev.Seq, last)
		}
		last = ev.Seq
		if ev.RunID != 7 {
			t.Fatalf("event is not attributed to run 7: %+v", ev)
		}
		if ev.At == "" {
			t.Fatalf("event has no timestamp: %+v", ev)
		}
		phases[ev.Phase] = true
	}
	// A run that stops must say why: the last event is the stop.
	lastEv := events[len(events)-1]
	if lastEv.Phase != PhaseStop || lastEv.Stop == "" {
		t.Fatalf("the stream does not end with a stop: %+v", lastEv)
	}
	if !phases[PhaseExec] {
		t.Fatalf("no execution events: %v", phases)
	}
}

// TestStepEventCarriesNoBody is the red line for this feature: the projection the
// UI sees must never contain a response body, a cookie or a credential.
func TestStepEventCarriesNoBody(t *testing.T) {
	rec := StepRecord{
		IntentID: 5, Capability: "probe", Tier: 1, Facts: 1, Findings: 2,
		RequestIDs: []string{"R0001-abc"},
	}
	args := map[string]any{"url": "https://target.example/search?q=secret-token&id=7"}
	ev := eventForRecord(3, args, rec)

	if strings.Contains(ev.Target, "secret-token") || strings.Contains(ev.Target, "id=7") {
		t.Fatalf("the event leaked a query value: %q", ev.Target)
	}
	if !strings.Contains(ev.Target, "q=…") {
		t.Fatalf("the event should keep the parameter names: %q", ev.Target)
	}
	if ev.RequestID != "R0001-abc" {
		t.Fatalf("request id missing: %+v", ev)
	}
	if ev.Status != "ok" || ev.Summary == "" {
		t.Fatalf("a hit should read as ok with a summary: %+v", ev)
	}
	// The struct has no field that could hold a body: assert the shape stays small.
	if strings.Contains(strings.ToLower(ev.Summary), "http/1.1") {
		t.Fatalf("summary looks like a response: %q", ev.Summary)
	}
}

// TestStepEventMarksAMiss: a step that found nothing says so, and does not invent
// a reason to look again.
func TestStepEventMarksAMiss(t *testing.T) {
	ev := eventForRecord(1, map[string]any{"url": "https://t.example/x"}, StepRecord{
		IntentID: 2, Capability: "param", Tier: 2,
	})
	if ev.Status != "miss" {
		t.Fatalf("status = %q, want miss", ev.Status)
	}
	if strings.Contains(ev.Summary, "可能") || strings.Contains(ev.Summary, "建议") {
		t.Fatalf("a miss is spun into a suggestion: %q", ev.Summary)
	}
}

// TestNoHookMeansNoChange: with OnStep nil the run is exactly what it was.
func TestNoHookMeansNoChange(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 4})
	rep, err := eng.Run(context.Background(), 1)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if eng.stepSeq != 0 {
		t.Fatalf("events were counted without a listener: %d", eng.stepSeq)
	}
	if rep.Stop == "" {
		t.Fatalf("the run did not report a stop: %+v", rep)
	}
}

// TestSanitiseTargetURL is a table test for the projection rule.
func TestSanitiseTargetURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://u:pw@h.example/a/b?x=1&y=2#frag", "https://h.example/a/b?x&y=…"},
		{"http://127.0.0.1:18080/login", "http://127.0.0.1:18080/login"},
		{"/relative/path?token=abc", "/relative/path"},
	}
	for _, c := range cases {
		if got := sanitiseTargetURL(c.in); got != c.want {
			t.Errorf("sanitiseTargetURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
