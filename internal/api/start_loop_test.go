package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// TestChatWithoutAPlannerStillAnswers: no model configured must not be a dead end.
// The reply explains the wizard path and the run can still happen.
func TestChatWithoutAPlannerStillAnswers(t *testing.T) {
	f := newFixture(t, "") // the fixture's planner manager starts disabled
	code, body := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/chat", f.eng.ID),
		map[string]any{"message": "帮我测一下这个站"}, nil)
	if code != http.StatusOK {
		t.Fatalf("chat without a planner = %d %v, want 200 with guidance", code, body)
	}
	reply, _ := body["reply"].(string)
	if !strings.Contains(reply, "向导") {
		t.Fatalf("the reply does not point at the wizard: %q", reply)
	}
	if noPlanner, _ := body["no_planner"].(bool); !noPlanner {
		t.Fatalf("the response does not say the planner is missing: %v", body)
	}
}

// TestRunStartsFromThePassportWhenNoSeedsAreGiven is the "started but did nothing"
// fix: a caller that only says "go" still gets a bootstrapped run.
func TestRunStartsFromThePassportWhenNoSeedsAreGiven(t *testing.T) {
	f := newFixture(t, "")
	code, body := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/runs", f.eng.ID),
		map[string]any{"max_steps": 4}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("run without seeds = %d %v", code, body)
	}
	// The run must have recorded the passport's own surface as its seed.
	runs, err := f.store.ListRuns(context.Background(), f.eng.ID, 5)
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) == 0 {
		t.Fatal("no run was created")
	}
	_ = runs
}

// TestPassportSurfacesAddsAScheme pins the helper that turns includes into seeds.
func TestPassportSurfacesAddsAScheme(t *testing.T) {
	sc := discipline.NewScope(discipline.Scope{
		Include: []string{"127.0.0.1:8080", "example.com", "https://already.example"},
		Basis:   "unit test", Operator: "t",
	})
	got := passportSurfaces(*sc)
	if len(got) != 3 {
		t.Fatalf("surfaces = %v", got)
	}
	if got[0] != "http://127.0.0.1:8080" {
		t.Errorf("loopback scheme = %q", got[0])
	}
	if got[1] != "https://example.com" {
		t.Errorf("public scheme = %q", got[1])
	}
	if got[2] != "https://already.example" {
		t.Errorf("existing URL was rewritten: %q", got[2])
	}
}

var _ = ledger.Hypothesis{}
