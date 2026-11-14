package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// seedReportLedger puts one complete (verified) and one incomplete candidate into
// the ledger, with audit rows for the former.
func seedReportLedger(t *testing.T, f *fixture) (verifiedID, candidateID int64) {
	t.Helper()
	ctx := context.Background()
	// The audit row the verified finding will cite. request_id is unique platform
	// wide (it is the audit anchor), so each test run gets its own.
	rid := fmt.Sprintf("R-%d", time.Now().UnixNano())
	if err := f.store.Record(ctx, discipline.AuditEvent{
		Engagement: f.eng.Name, RequestID: rid, Method: "GET",
		URL: "http://127.0.0.1:18080/orders/2", Host: "127.0.0.1:18080",
		Status: 200, Verdict: discipline.VerdictAllowed, Purpose: "compare:a",
		TS: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("audit: %v", err)
	}
	res, err := f.store.Ingest(ctx, f.eng.ID, nil, nil, ledger.Observation{
		Findings: []ledger.FindingSeed{
			{
				Title: "双账号可见同一标记", Severity: "high", Kind: "bola",
				Where:  "http://127.0.0.1:18080/orders/2",
				Detail: "bob 读到了 alice 的对象", Counter: "",
				Evidence: map[string]any{"request_id": rid},
			},
			{
				Title: "反射参数", Severity: "low", Kind: "reflection",
				Where:    "http://127.0.0.1:18080/search?q=x",
				Evidence: map[string]any{},
			},
		},
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	verifiedID = res.FindingIDs[0]
	candidateID = res.FindingIDs[1]
	return verifiedID, candidateID
}

// TestReportSnapshotsAreImmutable: a snapshot can be created, listed and read, but
// never updated - that is the whole point.
func TestReportSnapshotsAreImmutable(t *testing.T) {
	f := newFixture(t, "")
	seedReportLedger(t, f)
	ctx := context.Background()

	code, body := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/reports", f.eng.ID), nil, nil)
	if code != http.StatusCreated {
		t.Fatalf("create snapshot = %d %v", code, body)
	}
	sha, _ := body["sha256"].(string)
	if len(sha) != 64 {
		t.Fatalf("sha256 = %q", sha)
	}
	if p, ok := body["artifact"].(string); ok && p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("the HTML artefact was reported but is missing: %v", err)
		}
	}

	// Two snapshots, two rows, same hash when the ledger did not change.
	code, _ = f.do(t, http.MethodPost, fmt.Sprintf("/api/engagements/%d/reports", f.eng.ID), nil, nil)
	if code != http.StatusCreated {
		t.Fatalf("second snapshot = %d", code)
	}
	// The endpoint returns a bare array; f.do decodes into map[string]any, so read
	// the list through a direct request.
	req, _ := http.NewRequest(http.MethodGet,
		fmt.Sprintf("http://127.0.0.1/api/engagements/%d/reports", f.eng.ID), nil)
	req.Header.Set("X-Youkai-Token", f.token)
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var snaps []any
	if err := json.Unmarshal(raw, &snaps); err != nil {
		t.Fatalf("snapshot list is not an array: %s", raw)
	}
	if len(snaps) != 2 {
		t.Fatalf("snapshots = %d, want 2", len(snaps))
	}

	// Immutability is enforced by the database, not by politeness.
	for _, stmt := range []string{
		`UPDATE report_snapshots SET content_sha256='x'`,
		`DELETE FROM report_snapshots`,
	} {
		if _, err := f.store.Pool().Exec(ctx, stmt); err == nil {
			t.Fatalf("%q was allowed on an append-only table", stmt)
		}
	}
}

// TestSnapshotsCarryScopeAndChangeWithIt.
func TestSnapshotsCarryScopeAndChangeWithIt(t *testing.T) {
	f := newFixture(t, "")
	seedReportLedger(t, f)
	ctx := context.Background()

	if code, body := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/reports", f.eng.ID), nil, nil); code != http.StatusCreated {
		t.Fatalf("snapshot = %d %v", code, body)
	}
	var scope1 []byte
	if err := f.store.Pool().QueryRow(ctx,
		`SELECT scope_snapshot FROM report_snapshots ORDER BY id DESC LIMIT 1`).Scan(&scope1); err != nil {
		t.Fatalf("read scope: %v", err)
	}

	// Widen the passport, then snapshot again: the stored scope must differ.
	newScope := map[string]any{
		"project": "lab", "include": []string{"127.0.0.1", "lab.example"},
		"basis": "self-hosted lab, widened", "operator": "tester",
		"allow_private": true, "allow_active_probes": true,
		"expires_at": "2099-01-01T00:00:00Z",
	}
	if code, body := f.do(t, http.MethodPut,
		fmt.Sprintf("/api/engagements/%d/scope", f.eng.ID), map[string]any{"scope": newScope}, nil); code != http.StatusOK {
		t.Fatalf("scope edit = %d %v", code, body)
	}
	if code, body := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/reports", f.eng.ID), nil, nil); code != http.StatusCreated {
		t.Fatalf("second snapshot = %d %v", code, body)
	}
	var scope2 []byte
	if err := f.store.Pool().QueryRow(ctx,
		`SELECT scope_snapshot FROM report_snapshots ORDER BY id DESC LIMIT 1`).Scan(&scope2); err != nil {
		t.Fatalf("read scope 2: %v", err)
	}
	if string(scope1) == string(scope2) {
		t.Fatal("the snapshot did not freeze the passport it was produced under")
	}
	if !strings.Contains(string(scope2), "lab.example") {
		t.Fatalf("scope snapshot 2 = %s", scope2)
	}
}

func TestReportRenderingIsStableAcrossCalls(t *testing.T) {
	f := newFixture(t, "")
	seedReportLedger(t, f)
	url := fmt.Sprintf("/api/engagements/%d/report?format=md", f.eng.ID)
	get := func() string {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1"+url, nil)
		req.Header.Set("X-Youkai-Token", f.token)
		res, err := f.client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer res.Body.Close()
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		return buf.String()
	}
	a, b := get(), get()
	if a != b {
		t.Fatal("two renders of an unchanged ledger differ (snapshots would be uncheckable)")
	}
	if !strings.Contains(a, "① 证据") {
		t.Fatal("the report does not carry the four evidence sections")
	}
}

func TestSARIFEndpoint(t *testing.T) {
	f := newFixture(t, "")
	seedReportLedger(t, f)
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1/api/engagements/%d/sarif", f.eng.ID), nil)
	req.Header.Set("X-Youkai-Token", f.token)
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "sarif") {
		t.Fatalf("content-type = %q", ct)
	}
	raw, _ := io.ReadAll(res.Body)
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				Level string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("sarif is not JSON: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 2 {
		t.Fatalf("sarif shape = %+v", doc)
	}
}

// TestDisclosureRefusesCandidates: with nothing verified there is no disclosure,
// and the refusal says why rather than shipping an empty shell.
func TestDisclosureRefusesCandidates(t *testing.T) {
	f := newFixture(t, "")
	verifiedID, _ := seedReportLedger(t, f)

	code, body := f.do(t, http.MethodGet,
		fmt.Sprintf("/api/engagements/%d/disclosure", f.eng.ID), nil, nil)
	if code != http.StatusConflict {
		t.Fatalf("disclosure with only candidates = %d %v", code, body)
	}

	// Verify one finding: now a disclosure exists, and it contains only that one.
	code, _ = f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/findings/%d/verdict", f.eng.ID, verifiedID),
		map[string]any{"operator": "alice", "note": "复现确认", "confirm": true}, nil)
	if code != http.StatusOK {
		t.Fatalf("verdict = %d", code)
	}

	req, _ := http.NewRequest(http.MethodGet,
		fmt.Sprintf("http://127.0.0.1/api/engagements/%d/disclosure", f.eng.ID), nil)
	req.Header.Set("X-Youkai-Token", f.token)
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	doc := string(raw)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("disclosure = %d %s", res.StatusCode, doc)
	}
	if strings.Contains(doc, "反射参数") {
		t.Fatal("a candidate leaked into the disclosure")
	}
	if !strings.Contains(doc, "授权声明") {
		t.Fatal("the disclosure has no authorisation statement")
	}
	if !strings.Contains(doc, "估计") {
		t.Fatal("CVSS is not labelled as an estimate")
	}
}
