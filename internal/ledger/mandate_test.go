package ledger

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"youkai/internal/discipline"
)

func mandateTestStore(t *testing.T) (*Store, context.Context) {
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

// TestMandateLifecycle: active while in force, gone the moment it is stopped or
// expired. There is no cache to invalidate - "stop" is one column.
func TestMandateLifecycle(t *testing.T) {
	store, ctx := mandateTestStore(t)
	eng, err := store.CreateEngagement(ctx, "mandate-test-"+time.Now().Format("150405.000000"),
		map[string]any{"include": []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() { _, _ = store.Pool().Exec(context.Background(), `DELETE FROM engagements WHERE id=$1`, eng.ID) })

	payload := json.RawMessage(`{"schema":"FairyHighAuth/v1","assets":["127.0.0.1"],"actions":["read-only","tier2:param"]}`)

	// No mandate yet.
	if _, err := store.ActiveMandate(ctx, eng.ID); err != ErrNotFound {
		t.Fatalf("fresh engagement has an active mandate: %v", err)
	}

	m, err := store.SaveMandate(ctx, eng.ID, payload, "deadbeef",
		[]string{"127.0.0.1"}, []string{"param"}, 500, time.Now().Add(time.Hour), "alice", "self-hosted lab")
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if !m.Active(time.Now()) {
		t.Fatal("a fresh mandate is not active")
	}
	if !m.CoversClass("param") || m.CoversClass("waf") {
		t.Fatalf("class coverage = %+v", m.Classes)
	}

	active, err := store.ActiveMandate(ctx, eng.ID)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active.ID != m.ID || active.MaxRequests != 500 || active.Approver != "alice" {
		t.Fatalf("active mandate = %+v", active)
	}
	// The signed payload survives intact. JSONB normalises key order, and that is
	// fine: the signature is over a canonical (sorted-key) form, so re-verifying a
	// stored payload produces the same bytes. What must NOT happen is losing a field.
	var want, got map[string]any
	if err := json.Unmarshal(payload, &want); err != nil {
		t.Fatalf("fixture payload: %v", err)
	}
	if err := json.Unmarshal(active.Payload, &got); err != nil {
		t.Fatalf("stored payload: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("payload lost fields: %s", active.Payload)
	}
	for k, v := range want {
		if _, ok := got[k]; !ok {
			t.Fatalf("payload lost %q: %s", k, active.Payload)
		}
		_ = v
	}

	// Stop: instant, and idempotent.
	n, err := store.StopMandate(ctx, eng.ID)
	if err != nil || n != 1 {
		t.Fatalf("stop = %d, %v", n, err)
	}
	if _, err := store.ActiveMandate(ctx, eng.ID); err != ErrNotFound {
		t.Fatalf("a stopped mandate is still active: %v", err)
	}
	if n, _ := store.StopMandate(ctx, eng.ID); n != 0 {
		t.Fatalf("second stop touched %d rows", n)
	}
}

// TestExpiredMandateIsNotActive: expiry is derived from the clock, not from
// anything a process could forget to clean up.
func TestExpiredMandateIsNotActive(t *testing.T) {
	store, ctx := mandateTestStore(t)
	eng, err := store.CreateEngagement(ctx, "mandate-exp-"+time.Now().Format("150405.000000"),
		map[string]any{"include": []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() { _, _ = store.Pool().Exec(context.Background(), `DELETE FROM engagements WHERE id=$1`, eng.ID) })

	m, err := store.SaveMandate(ctx, eng.ID, json.RawMessage(`{}`), "sig",
		[]string{"127.0.0.1"}, []string{"param"}, 10, time.Now().Add(2*time.Second), "alice", "short-lived")
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if !m.Active(time.Now()) {
		t.Fatal("mandate is not active at issue time")
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := store.ActiveMandate(ctx, eng.ID); err != ErrNotFound {
		t.Fatalf("expired mandate still active: %v", err)
	}
}

// TestMandateUsageCountsOnlyWhatLeftTheWire: the budget is measured from the audit
// log, so a plan cannot spend it and a blocked request cannot consume it.
func TestMandateUsageCountsOnlyWhatLeftTheWire(t *testing.T) {
	store, ctx := mandateTestStore(t)
	name := "mandate-usage-" + time.Now().Format("150405.000000")
	eng, err := store.CreateEngagement(ctx, name, map[string]any{"include": []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() { _, _ = store.Pool().Exec(context.Background(), `DELETE FROM engagements WHERE id=$1`, eng.ID) })

	since := time.Now().Add(-time.Minute)
	// Two allowed, one blocked (different request ids: the column is unique).
	// request_id is unique platform-wide, so the fixture ids carry the run's name.
	for i, verdict := range []string{"allowed", "allowed", "blocked"} {
		id := name + "-" + string(rune('A'+i))
		if err := store.Record(ctx, auditEventFor(name, id, verdict)); err != nil {
			t.Fatalf("record %s: %v", verdict, err)
		}
	}
	used, err := store.MandateUsage(ctx, name, since)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if used != 2 {
		t.Fatalf("usage = %d, want 2 (blocked requests do not spend budget)", used)
	}
}
func auditEventFor(engagement, requestID, verdict string) discipline.AuditEvent {
	return discipline.AuditEvent{
		Engagement: engagement, RequestID: requestID, Method: "GET",
		URL: "http://127.0.0.1/x", Host: "127.0.0.1:9", Status: 200,
		Verdict: verdict, Purpose: "test", TS: time.Now().UTC(),
	}
}
