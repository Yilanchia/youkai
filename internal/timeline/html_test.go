package timeline

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"youkai/internal/graph"
)

func buildGraph(t *testing.T) (*graph.Owner, *graph.Graph) {
	t.Helper()
	o, err := graph.Open(filepath.Join(t.TempDir(), "explore.json"))
	if err != nil {
		t.Fatalf("graph.Open: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })

	if _, err := o.Apply(graph.CmdAddNode(graph.NodeSeed{
		Kind:  graph.KindGoal,
		Props: map[string]any{"statement": "只读取证:demo"},
	})); err != nil {
		t.Fatalf("goal: %v", err)
	}
	if _, err := o.Apply(graph.CmdAddFact(graph.FactSeed{
		Statement: `probe found <script>alert("x")</script> in the body`,
		Evidence: map[string]any{
			"request_id": "req-1",
			"audit_path": ".fairy/audit/run.jsonl",
			"cookie":     "session=supersecret",
		},
		Tags:    []string{"probe", "http"},
		Anchors: []string{"host:lab.invalid"},
	})); err != nil {
		t.Fatalf("fact: %v", err)
	}
	finding, err := o.Apply(graph.CmdAddNode(graph.NodeSeed{
		Kind: graph.KindFinding,
		Props: map[string]any{
			"title":          "参数 q 的值反射进响应",
			"severity":       "medium",
			"where":          "GET https://lab.invalid/s?q=1 (param: q)",
			"status":         "candidate",
			"evidence":       map[string]any{"request_id": "req-2"},
			"refutation":     "仅证明反射,未证明可逃逸上下文",
			"stop_condition": "浏览器确认上下文后即停",
		},
		Anchors: []string{"host:lab.invalid"},
	}))
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	_ = finding
	if _, err := o.Apply(graph.CmdAddNode(graph.NodeSeed{
		Kind: graph.KindIntent,
		Props: map[string]any{
			"action": "web_param",
			"args":   map[string]any{"urls": []string{"https://lab.invalid/s"}, "param": "q"},
			"tier":   2, "status": graph.StatusNeedsApproval,
			"rationale": "反射已观察到,确认是否可注入",
		},
		Anchors: []string{"host:lab.invalid"},
	})); err != nil {
		t.Fatalf("intent: %v", err)
	}
	// A done read-only intent, for the counts strip.
	if _, err := o.Apply(graph.CmdAddNode(graph.NodeSeed{
		Kind:  graph.KindIntent,
		Props: map[string]any{"action": "web_probe", "args": map[string]any{"url": "https://lab.invalid/.git/config"}, "tier": 1},
	})); err != nil {
		t.Fatalf("intent: %v", err)
	}
	return o, o.Snapshot()
}

func TestRenderSelfContained(t *testing.T) {
	_, g := buildGraph(t)
	out, err := Render(g, Options{Title: "demo engagement", GeneratedAt: time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	page := string(out)

	if !strings.HasPrefix(page, "<!DOCTYPE html>") {
		t.Fatal("not an HTML document")
	}
	// Self-contained: no scripts, no external resources.
	for _, bad := range []string{"<script", "src=", "http://www.w3.org/1999/xhtml", "@import"} {
		if strings.Contains(page, bad) {
			t.Fatalf("page is not self-contained: found %q", bad)
		}
	}
	if !strings.Contains(page, "demo engagement") {
		t.Fatal("title missing")
	}
	if !strings.Contains(page, "2026-11-13T09:00:00Z") {
		t.Fatal("pinned timestamp missing")
	}
}

func TestRenderEscapesTargetControlledText(t *testing.T) {
	_, g := buildGraph(t)
	out, _ := Render(g, Options{})
	page := string(out)

	if strings.Contains(page, "<script>alert") {
		t.Fatal("target-controlled text was rendered as live HTML (XSS in the evidence page)")
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Fatal("escaped statement not present")
	}
}

func TestRenderRedactsCredentialShapedProps(t *testing.T) {
	_, g := buildGraph(t)
	out, _ := Render(g, Options{})
	page := string(out)
	if strings.Contains(page, "supersecret") {
		t.Fatal("a session value leaked into the read-only report")
	}
	if !strings.Contains(page, "req-1") {
		t.Fatal("the request_id evidence pointer is missing")
	}
	if !strings.Contains(page, ".fairy/audit/run.jsonl") {
		t.Fatal("the audit path is missing")
	}
}

func TestRenderShowsTheDoorAndFindingEvidence(t *testing.T) {
	_, g := buildGraph(t)
	out, _ := Render(g, Options{})
	page := string(out)

	if !strings.Contains(page, "Stopped at the door") {
		t.Fatal("needs_approval intent is not surfaced")
	}
	if !strings.Contains(page, "needs_approval · tier 2") {
		t.Fatal("the parked intent's tier is not shown")
	}
	for _, want := range []string{"counter-evidence", "stop condition", "candidate", "req-2"} {
		if !strings.Contains(page, want) {
			t.Fatalf("finding evidence field %q missing", want)
		}
	}
	// The doc requires lineage in the page.
	if !strings.Contains(page, "lineage") || !strings.Contains(page, "host:lab.invalid") {
		t.Fatal("lineage / anchors missing")
	}
}

func TestRenderEmptyGraph(t *testing.T) {
	out, err := Render(graph.New(), Options{})
	if err != nil {
		t.Fatalf("Render(empty): %v", err)
	}
	if !strings.Contains(string(out), "Timeline") {
		t.Fatal("empty graph produced an unusable page")
	}
}
