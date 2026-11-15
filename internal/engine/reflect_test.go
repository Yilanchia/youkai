package engine

import (
	"context"
	"strings"
	"testing"

	"youkai/internal/ledger"
)

// TestReflectionIsHonestOnAMiss is the discipline this module exists for: a probe
// that found nothing must be reported as "not confirmed", not spun into a reason
// to keep digging.
func TestReflectionIsHonestOnAMiss(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 8})
	it := ledger.Intent{
		ID: 1, Capability: "param",
		Args: map[string]any{"url": "http://127.0.0.1/s?q=1", "hypothesis_id": float64(9)},
	}
	r := eng.reflectOn(it, StepRecord{IntentID: 1, Capability: "param", Findings: 0})
	if r == nil {
		t.Fatal("a miss produced no reflection at all")
	}
	if !strings.Contains(r.Line, "未被这次探测证实") {
		t.Fatalf("the miss is not described as a miss: %q", r.Line)
	}
	for _, banned := range []string{"可能还需要", "值得再试", "建议继续", "换个载荷"} {
		if strings.Contains(r.Statement, banned) {
			t.Fatalf("the reflection invents a reason to continue: %q", r.Statement)
		}
	}
	if !hasTag(r.Tags, "hypothesis-unconfirmed") {
		t.Fatalf("tags = %v, want hypothesis-unconfirmed", r.Tags)
	}
}

// TestReflectionConfirmsOnAHit: with evidence, the lead is upgraded, and the
// reflection names both kinds of evidence.
func TestReflectionConfirmsOnAHit(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 8})
	it := ledger.Intent{
		ID: 2, Capability: "param",
		Args: map[string]any{"url": "http://127.0.0.1/s?q=1", "hypothesis_id": float64(9)},
	}
	r := eng.reflectOn(it, StepRecord{
		IntentID: 2, Capability: "param", Findings: 2,
		RequestIDs: []string{"R0001-aa", "R0002-bb"},
	})
	if r == nil {
		t.Fatal("a hit produced no reflection")
	}
	if !strings.Contains(r.Statement, "双证据") {
		t.Fatalf("the reflection does not say the evidence is now two-sided: %q", r.Statement)
	}
	if !hasTag(r.Tags, "hypothesis-confirmed") {
		t.Fatalf("tags = %v", r.Tags)
	}
}

// TestReflectionIgnoresPlainSteps: nothing to say about a scan that changed no
// hypothesis, and silence is better than noise.
func TestReflectionIgnoresPlainSteps(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 8})
	if r := eng.reflectOn(ledger.Intent{ID: 3, Capability: "headers"},
		StepRecord{IntentID: 3, Capability: "headers", Findings: 1}); r != nil {
		t.Fatalf("a plain step produced a reflection: %+v", r)
	}
}

// TestReflectionLandsInTheGraph: the note is written where a human can find it.
func TestReflectionLandsInTheGraph(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 8})
	it := ledger.Intent{ID: 4, Capability: "param",
		Args: map[string]any{"url": "http://127.0.0.1/s?q=1", "hypothesis_id": float64(3)}}
	eng.recordReflection(context.Background(), it, StepRecord{IntentID: 4, Capability: "param"})
	var found bool
	for _, fact := range f.facts {
		if strings.Contains(fact.Statement, "复盘:白盒线索 #3 未被证实") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the reflection never reached the graph: %+v", f.facts)
	}
}
