package whitebox

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTree lays down a small app so the tests read like the thing they describe.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

const expressApp = `const express = require('express');
const app = express();
const db = require('./db');

app.get('/search', async (req, res) => {
  const q = req.query.q;
  const rows = await db.query("SELECT * FROM items WHERE name = '" + q + "'");
  res.send(rows);
});

app.get('/safe', requireAuth, async (req, res) => {
  const q = req.query.q;
  const rows = await db.query('SELECT * FROM items WHERE name = ?', [q]);
  res.send(rows);
});

app.post('/admin/delete', async (req, res) => {
  await db.query('DELETE FROM items WHERE id = ' + req.body.id);
  res.send({ ok: true });
});
`

// TestIngestFindsTheRouteTable: method, path, handler line and auth flag.
func TestIngestFindsTheRouteTable(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.js": expressApp})
	rep, err := Ingest(dir)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(rep.Routes) != 3 {
		t.Fatalf("routes = %d, want 3: %+v", len(rep.Routes), rep.Routes)
	}
	var got []string
	for _, r := range rep.Routes {
		got = append(got, r.Method+" "+r.Path)
		if r.File != "app.js" || r.Line == 0 {
			t.Errorf("route lacks file:line: %+v", r)
		}
	}
	want := map[string]bool{"GET /search": true, "GET /safe": true, "POST /admin/delete": true}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected route %q", g)
		}
	}
	for _, r := range rep.Routes {
		if r.Path == "/safe" && !r.Auth {
			t.Error("/safe should be marked authenticated (requireAuth middleware)")
		}
	}
}

// TestIngestProducesSinkHypotheses: the concatenated query becomes a lead, the
// parameterised one does not.
func TestIngestProducesSinkHypotheses(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.js": expressApp})
	rep, err := Ingest(dir)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var found *Hypothesis
	for i := range rep.Hypotheses {
		if rep.Hypotheses[i].Sink == "sql-concat" && rep.Hypotheses[i].Entry == "GET /search" {
			found = &rep.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("no sql-concat hypothesis for /search: %+v", rep.Hypotheses)
	}
	if found.Param != "q" {
		t.Errorf("param = %q, want q", found.Param)
	}
	if found.Confidence != "code-only" {
		t.Errorf("confidence = %q, want code-only", found.Confidence)
	}
	for _, h := range rep.Hypotheses {
		if h.Entry == "GET /safe" {
			t.Errorf("the parameterised query produced a lead: %+v", h)
		}
	}
}

// TestIngestFlagsMissingAuthz: a mutating route with no auth nearby is a lead.
func TestIngestFlagsMissingAuthz(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.js": expressApp})
	rep, err := Ingest(dir)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var flagged bool
	for _, h := range rep.Hypotheses {
		if h.Kind == "missing-authz" && h.Entry == "POST /admin/delete" {
			flagged = true
		}
		if h.Kind == "missing-authz" && h.Entry == "GET /safe" {
			t.Error("an authenticated route was flagged as missing auth")
		}
	}
	if !flagged {
		t.Fatalf("no missing-authz lead for the unprotected admin route: %+v", rep.Hypotheses)
	}
}

// TestIngestNeverKeepsSourceText: the ledger must not receive code or secrets.
func TestIngestNeverKeepsSourceText(t *testing.T) {
	src := `const express = require('express');
const app = express();
const key = "sk-live-abcdef123456";
app.get('/go', (req, res) => {
  const url = req.query.next;
  res.redirect(url);
});
`
	dir := writeTree(t, map[string]string{"app.js": src})
	rep, err := Ingest(dir)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	for _, h := range rep.Hypotheses {
		blob := h.Note + h.Path + h.Entry + h.Param + h.Sink
		if contains(blob, "sk-live") || contains(blob, "const express") {
			t.Fatalf("a hypothesis carries source text: %+v", h)
		}
	}
	for _, r := range rep.Routes {
		if contains(r.Path, "SELECT") || contains(r.Handler, "sk-live") {
			t.Fatalf("a route carries source text: %+v", r)
		}
	}
}

// TestIngestIgnoresVendorTrees: node_modules is not the application.
func TestIngestIgnoresVendorTrees(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"app.js":                    "const app = require('express')();\napp.get('/real', (q, s) => {});\n",
		"node_modules/pkg/index.js": "app.get('/vendored', (q, s) => {});\n",
	})
	rep, err := Ingest(dir)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	for _, r := range rep.Routes {
		if r.Path == "/vendored" {
			t.Fatal("a vendored tree was scanned")
		}
	}
}

// TestIngestRefusesAFile confirms the shape check: a file is not a source tree.
func TestIngestRefusesAFile(t *testing.T) {
	dir := writeTree(t, map[string]string{"a.js": "x"})
	if _, err := Ingest(filepath.Join(dir, "a.js")); err == nil {
		t.Fatal("ingest accepted a file path")
	}
}

func contains(h, n string) bool {
	return len(n) > 0 && len(h) >= len(n) && (indexOf(h, n) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
