package ledger

import (
	"context"
	"os"
	"testing"
)

func testDB(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("YOUKAI_TEST_DSN")
	if dsn == "" {
		dsn = "postgres://youkai:youkai_dev_pw@127.0.0.1:55432/youkai_test?sslmode=disable"
	}
	store, err := Open(ctx, dsn)
	if err != nil {
		t.Skipf("no PostgreSQL (%v)", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(store.Close)
	return store, ctx
}

// TestSearchTracesIsScopedOrderedAndFilterable is the v0.7 acceptance test for the
// retrieval side: one engagement's memory never leaks into another's.
func TestSearchTracesIsScopedOrderedAndFilterable(t *testing.T) {
	store, ctx := testDB(t)

	one, err := store.CreateEngagement(ctx, "trace-one", map[string]any{"include": []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	two, err := store.CreateEngagement(ctx, "trace-two", map[string]any{"include": []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	mk := func(engID int64, cap string, args map[string]any, trace string) Intent {
		t.Helper()
		it, _, err := store.EnsureIntent(ctx, engID, IntentSpec{
			Capability: cap, Args: args, Tier: 1, Rationale: "test",
		})
		if err != nil {
			t.Fatalf("ensure intent: %v", err)
		}
		if err := store.SetIntentStatus(ctx, engID, it.ID, StatusDone); err != nil {
			t.Fatalf("status: %v", err)
		}
		if err := store.AppendTrace(ctx, engID, it.ID, trace); err != nil {
			t.Fatalf("trace: %v", err)
		}
		return it
	}

	a := mk(one.ID, "probe", map[string]any{"url": "http://127.0.0.1:18080/.git/config"},
		"capability=probe ok=true tier=1 facts=1 findings=1 request_ids=R0001-aaaa,R0002-bbbb")
	b := mk(one.ID, "scan", map[string]any{"url": "http://127.0.0.1:18080/search?q=x"},
		"capability=scan ok=true tier=1 facts=9 findings=7 request_ids=R0003-cccc")
	mk(two.ID, "probe", map[string]any{"url": "http://127.0.0.1:18080/.git/config"},
		"capability=probe ok=true tier=1 facts=1 findings=1 request_ids=R9999-zzzz")

	all, err := store.SearchTraces(ctx, one.ID, TraceQuery{})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("hits = %d, want 2 (cross-engagement leak?): %+v", len(all), all)
	}
	if all[0].IntentID != a.ID || all[1].IntentID != b.ID {
		t.Fatalf("not ordered by intent id: %+v", all)
	}
	// Deterministic: a second call returns the same thing.
	again, _ := store.SearchTraces(ctx, one.ID, TraceQuery{})
	if len(again) != len(all) || again[0].IntentID != all[0].IntentID {
		t.Fatal("search is not deterministic")
	}

	// Target normalisation: host+path, no scheme, no query.
	if all[0].Target != "127.0.0.1:18080/.git/config" {
		t.Fatalf("probe target = %q", all[0].Target)
	}
	if all[1].Target != "127.0.0.1:18080/search" {
		t.Fatalf("scan target = %q", all[1].Target)
	}
	if len(all[0].RequestIDs) != 2 || all[0].RequestIDs[0] != "R0001-aaaa" {
		t.Fatalf("request ids = %v", all[0].RequestIDs)
	}
	if all[0].Summary == "" || all[0].At == "" {
		t.Fatalf("hit is missing its summary/time: %+v", all[0])
	}
	// No raw args, no body, nothing secret: the summary is the trace line.
	if len(all[0].Summary) > 300 {
		t.Fatalf("summary is not bounded: %d chars", len(all[0].Summary))
	}

	byCap, _ := store.SearchTraces(ctx, one.ID, TraceQuery{Capability: "probe"})
	if len(byCap) != 1 || byCap[0].Capability != "probe" {
		t.Fatalf("capability filter = %+v", byCap)
	}
	byHost, _ := store.SearchTraces(ctx, one.ID, TraceQuery{Host: "127.0.0.1:18080"})
	if len(byHost) != 2 {
		t.Fatalf("host filter = %+v", byHost)
	}
	if none, _ := store.SearchTraces(ctx, one.ID, TraceQuery{Host: "10.0.0.1"}); len(none) != 0 {
		t.Fatalf("unknown host returned %+v", none)
	}
	byKW, _ := store.SearchTraces(ctx, one.ID, TraceQuery{Keyword: "findings=7"})
	if len(byKW) != 1 || byKW[0].Capability != "scan" {
		t.Fatalf("keyword filter = %+v", byKW)
	}

	// Empty result is not an error.
	if empty, err := store.SearchTraces(ctx, one.ID, TraceQuery{Capability: "crawl"}); err != nil || len(empty) != 0 {
		t.Fatalf("empty search = %v, %v", empty, err)
	}

	// Limit keeps the most recent tail and stays stable.
	limited, _ := store.SearchTraces(ctx, one.ID, TraceQuery{Limit: 1})
	if len(limited) != 1 || limited[0].IntentID != b.ID {
		t.Fatalf("limit did not keep the newest: %+v", limited)
	}

	// Covered: the derivation guard's question.
	if !Covered(all, "probe", "127.0.0.1:18080/.git/config") {
		t.Fatal("Covered missed a completed probe")
	}
	if Covered(all, "probe", "127.0.0.1:18080/other") {
		t.Fatal("Covered matched the wrong endpoint")
	}
	if Covered(all, "crawl", "127.0.0.1:18080/.git/config") {
		t.Fatal("Covered matched the wrong capability")
	}
}
