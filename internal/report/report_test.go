package report

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"youkai/internal/ledger"
)

// fixture builds one audit row that a finding can cite.
func auditRow(id, method, rawURL, verdict, purpose string) ledger.AuditRow {
	host := "127.0.0.1"
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host = u.Host
	}
	return ledger.AuditRow{
		RequestID: id, Method: method, URL: rawURL, Host: host,
		Status: 200, Verdict: verdict, Purpose: purpose,
		TS: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC),
	}
}

func baseBundle() Bundle {
	return Build(Input{
		Engagement: "lab",
		Scope:      json.RawMessage(`{"basis":"self-hosted lab","include":["127.0.0.1"]}`),
		Provider:   "no exploitation provider in this build",
		Stats:      ledger.GraphStats{Assets: 1, Facts: 2, Findings: 2, Verified: 1},
		Findings: []ledger.Finding{
			{
				ID: 1, Title: "双账号可见同一标记(BOLA/IDOR 候选)", Severity: "high", Kind: "bola",
				Where: "http://127.0.0.1:18080/orders/2", Detail: "bob 读到了 alice 的对象",
				State: ledger.FindingVerified, Counter: "",
				Evidence: map[string]any{"request_id": "R-001"},
			},
			{
				ID: 2, Title: "反射参数", Severity: "low", Kind: "reflection",
				Where: "http://127.0.0.1:18080/search?q=x",
				State: ledger.FindingCandidate,
				// Deliberately missing a counter and citing nothing: must be incomplete.
				Evidence: map[string]any{},
			},
		},
		Intents: []ledger.Intent{{ID: 7, Capability: "compare", Tier: 1, Status: "done"}},
		Audit: []ledger.AuditRow{
			auditRow("R-001", "GET", "http://127.0.0.1:18080/orders/2", verdictAllowed, "compare:a"),
			auditRow("R-002", "GET", "http://127.0.0.1:18080/search?q=x", verdictAllowed, "probe"),
		},
	})
}

// TestFourEvidenceGrading: every finding carries the four pieces, and a finding
// that cannot is marked, not silently trusted.
func TestFourEvidenceGrading(t *testing.T) {
	b := baseBundle()
	if len(b.Findings) != 2 {
		t.Fatalf("findings = %d", len(b.Findings))
	}
	ok := b.Findings[0]
	if !ok.Evidence.Complete {
		t.Fatalf("finding 1 evidence incomplete: %+v", ok.Evidence)
	}
	if len(ok.Evidence.Audit) != 1 || ok.Evidence.Audit[0].RequestID != "R-001" {
		t.Fatalf("evidence did not resolve the audit row: %+v", ok.Evidence)
	}
	if ok.Capability != "compare" {
		t.Fatalf("capability = %q", ok.Capability)
	}
	if ok.MinImpact == "" || strings.HasPrefix(ok.MinImpact, "unknown") {
		t.Fatalf("min impact = %q", ok.MinImpact)
	}
	if ok.StopCondition == "" {
		t.Fatal("stop condition missing")
	}
	if ok.Counter == "" {
		t.Fatal("counter template did not fill for kind=bola")
	}
	if len(ok.Incomplete) != 0 {
		t.Fatalf("complete finding marked incomplete: %v", ok.Incomplete)
	}
	if !ok.Disclosable {
		t.Fatal("a verified finding with four pieces must be disclosable")
	}

	bad := b.Findings[1]
	if bad.Evidence.Complete {
		t.Fatal("finding with no request_id was graded complete")
	}
	joined := strings.Join(bad.Incomplete, ",")
	for _, want := range []string{"evidence"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("incomplete = %v, want %q", bad.Incomplete, want)
		}
	}
	if bad.Disclosable {
		t.Fatal("an incomplete candidate must not be disclosable")
	}
	if len(b.Incomplete) != 1 || !strings.Contains(b.Incomplete[0], "finding #2") {
		t.Fatalf("bundle incomplete list = %v", b.Incomplete)
	}
}

func TestMissingCounterIsReported(t *testing.T) {
	b := Build(Input{
		Engagement: "lab",
		Findings: []ledger.Finding{{
			ID: 9, Title: "unknown thing", Kind: "no-such-kind", Severity: "info",
			State: ledger.FindingCandidate, Evidence: map[string]any{"request_id": "R-1"},
		}},
		Audit: []ledger.AuditRow{auditRow("R-1", "GET", "http://127.0.0.1/x", verdictAllowed, "probe")},
	})
	got := b.Findings[0]
	found := false
	for _, inc := range got.Incomplete {
		if inc == "counter" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing counter not reported: %v", got.Incomplete)
	}
}

func TestMissingAuditRowIsReported(t *testing.T) {
	b := Build(Input{
		Engagement: "lab",
		Findings: []ledger.Finding{{
			ID: 3, Title: "claims a request", Kind: "bola", Severity: "high",
			Evidence: map[string]any{"request_id": "R-DOES-NOT-EXIST"},
		}},
	})
	got := b.Findings[0]
	if got.Evidence.Complete {
		t.Fatal("a cited-but-absent request was graded complete")
	}
	if len(got.Evidence.Missing) != 1 || got.Evidence.Missing[0] != "R-DOES-NOT-EXIST" {
		t.Fatalf("missing = %v", got.Evidence.Missing)
	}
}

// TestCoverageComesFromTheAudit: coverage counts requests that happened, never the
// scope's ambitions.
func TestCoverageComesFromTheAudit(t *testing.T) {
	b := Build(Input{
		Engagement: "lab",
		Scope:      json.RawMessage(`{"include":["a.example","b.example","c.example"]}`),
		Audit: []ledger.AuditRow{
			auditRow("R-1", "GET", "http://a.example/x?q=1", verdictAllowed, "probe"),
			auditRow("R-2", "GET", "http://a.example/x?q=2", verdictAllowed, "probe"),
			auditRow("R-3", "GET", "http://b.example/y", verdictBlocked, "browser"),
		},
	})
	if b.Coverage.Requests != 3 || b.Coverage.Allowed != 2 || b.Coverage.Blocked != 1 {
		t.Fatalf("coverage counts = %+v", b.Coverage)
	}
	if b.Coverage.Endpoints != 2 {
		t.Fatalf("endpoints = %d, want 2 (query strings must not fork the count): %v",
			b.Coverage.Endpoints, b.Coverage.EndpointList)
	}
	if len(b.Coverage.Hosts) != 2 {
		t.Fatalf("hosts = %v", b.Coverage.Hosts)
	}
	for _, banned := range []string{"全站", "完整覆盖", "全部资产"} {
		if strings.Contains(b.Coverage.Statement, banned) {
			t.Fatalf("coverage statement overclaims (%q): %s", banned, b.Coverage.Statement)
		}
	}
	if !strings.Contains(b.Coverage.Statement, "未在此列出的资产不在本报告范围内") {
		t.Fatalf("coverage statement is not explicit about the boundary: %s", b.Coverage.Statement)
	}
}

// TestRenderingIsDeterministic: the same bundle renders the same bytes, which is
// what makes a snapshot checkable by hash.
func TestRenderingIsDeterministic(t *testing.T) {
	a := baseBundle()
	b := baseBundle()
	md1, md2 := Markdown(a), Markdown(b)
	if md1 != md2 {
		t.Fatal("markdown rendering is not deterministic")
	}
	html1, html2 := HTML(a), HTML(b)
	if html1 != html2 {
		t.Fatal("html rendering is not deterministic")
	}
	h1, err := Hash(a)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h2, _ := Hash(b)
	if h1 != h2 {
		t.Fatalf("hash differs for the same ledger: %s vs %s", h1, h2)
	}
	// A changed ledger must change the hash.
	c := baseBundle()
	c.Findings[0].Title = "changed"
	h3, _ := Hash(c)
	if h3 == h1 {
		t.Fatal("hash did not change when the ledger did")
	}
}

func TestMarkdownCarriesTheFourSections(t *testing.T) {
	md := Markdown(baseBundle())
	for _, want := range []string{"① 证据", "② 最小影响", "③ 停止点", "④ 反证说明"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown is missing %q", want)
		}
	}
	if !strings.Contains(md, "证据不完整") {
		t.Fatal("markdown does not flag incomplete findings")
	}
	if !strings.Contains(md, "覆盖:") {
		t.Fatal("markdown has no coverage statement")
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	page := HTML(baseBundle())
	if strings.Contains(page, "<script") {
		t.Fatal("the report HTML contains a script")
	}
	for _, bad := range []string{"http://cdn", "https://cdn", "<link rel=\"stylesheet\"", "@import"} {
		if strings.Contains(page, bad) {
			t.Fatalf("the report HTML reaches out (%q)", bad)
		}
	}
	if !strings.Contains(page, "<style>") {
		t.Fatal("the report HTML has no inline style")
	}
	// Escaping: a finding title with markup must not become markup.
	b := baseBundle()
	b.Findings[0].Title = `<script>alert(1)</script>`
	if strings.Contains(HTML(b), "<script>alert(1)</script>") {
		t.Fatal("HTML rendering did not escape the finding title")
	}
}

// ---- SARIF -----------------------------------------------------------------

func sarifDoc(t *testing.T, b Bundle) map[string]any {
	t.Helper()
	raw, err := SARIF(b)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	return doc
}

// TestSARIFShape checks the 2.1.0 required structure without pretending to run the
// full JSON-Schema validator.
func TestSARIFShape(t *testing.T) {
	b := baseBundle()
	// Make finding 2 file:line shaped, to prove binary locations work too.
	b.Findings = append(b.Findings, FindingReport{
		Finding: ledger.Finding{
			ID: 3, Title: "栈溢出候选", Kind: "binary", Severity: "high",
			Where:    "artifacts/sample.bin:42",
			State:    ledger.FindingCandidate,
			Evidence: map[string]any{"request_id": "R-001"},
		},
	})
	doc := sarifDoc(t, b)
	if doc["version"] != "2.1.0" {
		t.Fatalf("version = %v", doc["version"])
	}
	if _, ok := doc["$schema"]; !ok {
		t.Fatal("missing $schema")
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v", doc["runs"])
	}
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "youkai" {
		t.Fatalf("driver name = %v", driver["name"])
	}
	if _, ok := driver["rules"].([]any); !ok {
		t.Fatal("no rules array")
	}
	results := run["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("results = %d", len(results))
	}

	var sawError, sawWarning, sawFileLine, sawParam bool
	for _, r := range results {
		res := r.(map[string]any)
		for _, key := range []string{"ruleId", "level", "message", "locations"} {
			if _, ok := res[key]; !ok {
				t.Fatalf("result missing %q: %v", key, res)
			}
		}
		level := res["level"].(string)
		if level == "error" {
			sawError = true
		}
		if level == "warning" {
			sawWarning = true
		}
		locs := res["locations"].([]any)
		loc := locs[0].(map[string]any)
		phys := loc["physicalLocation"].(map[string]any)
		region := phys["region"].(map[string]any)
		if region["startLine"].(float64) < 1 {
			t.Fatal("region.startLine must be >= 1")
		}
		uri := phys["artifactLocation"].(map[string]any)["uri"].(string)
		if strings.HasPrefix(uri, "artifacts/") {
			sawFileLine = true
		}
		if logical, ok := loc["logicalLocations"].([]any); ok {
			for _, l := range logical {
				if m, ok := l.(map[string]any); ok && strings.HasPrefix(toStr(m["name"]), "param:") {
					sawParam = true
				}
			}
		}
		props := res["properties"].(map[string]any)
		for _, key := range []string{"min_impact", "stop_condition", "counter", "request_ids"} {
			if _, ok := props[key]; !ok {
				t.Fatalf("SARIF properties missing %q (the four must survive the export)", key)
			}
		}
	}
	if !sawError {
		t.Fatal("a verified finding must map to level=error")
	}
	if !sawWarning {
		t.Fatal("a candidate must map to level=warning")
	}
	if !sawFileLine {
		t.Fatal("binary file:line location was not produced")
	}
	if !sawParam {
		t.Fatal("web parameter logical location was not produced")
	}
}

func TestSARIFIsDeterministic(t *testing.T) {
	a, err := SARIF(baseBundle())
	if err != nil {
		t.Fatal(err)
	}
	b, err := SARIF(baseBundle())
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("SARIF export is not deterministic (rules must be sorted)")
	}
}

func toStr(v any) string {
	s, _ := v.(string)
	return s
}

// ---- disclosure ------------------------------------------------------------

func TestDisclosureOnlyContainsVerified(t *testing.T) {
	b := baseBundle()
	scope := ParseScope(b.Scope)
	md, err := DisclosureMarkdown(b, scope)
	if err != nil {
		t.Fatalf("Disclosure: %v", err)
	}
	if !strings.Contains(md, "BOLA") {
		t.Fatal("the verified finding is missing from the disclosure")
	}
	if strings.Contains(md, "反射参数") {
		t.Fatal("a candidate leaked into the disclosure")
	}
	if !strings.Contains(md, "估计") {
		t.Fatal("CVSS is not marked as an estimate")
	}
	if !strings.Contains(md, "授权声明") || !strings.Contains(md, "self-hosted lab") {
		t.Fatal("the authorisation statement is missing")
	}
	// The evidence pointer is present; the raw response never is.
	if !strings.Contains(md, "R-001") {
		t.Fatal("the disclosure does not name the evidence anchor")
	}
}

func TestDisclosureRefusesWithoutVerifiedOrScope(t *testing.T) {
	// Only candidates: refuse with a clear reason.
	onlyCandidates := baseBundle()
	onlyCandidates.Findings = onlyCandidates.Findings[1:]
	if _, err := DisclosureMarkdown(onlyCandidates, ParseScope(onlyCandidates.Scope)); err == nil {
		t.Fatal("disclosure was produced with no verified findings")
	} else if _, ok := err.(ErrNoVerified); !ok {
		t.Fatalf("error = %T %v, want ErrNoVerified", err, err)
	}

	// No basis: refuse, because a disclosure without authorisation is an accusation.
	b := baseBundle()
	b.Scope = json.RawMessage(`{"include":["127.0.0.1"]}`)
	if _, err := DisclosureHTML(b, ParseScope(b.Scope)); err == nil {
		t.Fatal("disclosure was produced without an authorisation basis")
	} else if _, ok := err.(ErrNoAuthorisation); !ok {
		t.Fatalf("error = %T %v, want ErrNoAuthorisation", err, err)
	}
}

func TestDisclosureHTMLHasNoExternalRefs(t *testing.T) {
	b := baseBundle()
	page, err := DisclosureHTML(b, ParseScope(b.Scope))
	if err != nil {
		t.Fatalf("DisclosureHTML: %v", err)
	}
	if strings.Contains(page, "<script") || strings.Contains(page, "<link rel=\"stylesheet\"") {
		t.Fatal("disclosure HTML is not self-contained")
	}
}
