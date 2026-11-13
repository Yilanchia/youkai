// Package timeline renders the exploration graph as a self-contained, read-only
// HTML page (module 7).
//
// Constraints inherited from ADR-001: no server, no network, no JavaScript
// dependency, no credentials, no response bodies. It is a document you can open
// from disk, diff, attach to a report, or hand to a reviewer who has none of your
// tooling.
package timeline

import (
	"bytes"
	"encoding/json"
	"html/template"
	"sort"
	"strings"
	"time"

	"youkai/internal/graph"
)

// Options tunes the render.
type Options struct {
	// Title is the page title (usually the engagement name).
	Title string
	// GeneratedAt overrides the timestamp (tests pin it).
	GeneratedAt time.Time
	// MaxStatementChars truncates long statements so the page stays readable.
	MaxStatementChars int
}

// nodeView is one row in the timeline.
type nodeView struct {
	ID        int64
	Kind      string
	Time      string
	Title     string
	Subtitle  string
	Status    string
	Tier      int
	Tags      []string
	Detail    string
	Anchors   []string
	Relations []string
	Evidence  []string
	// Finding-specific four-part evidence.
	Finding *findingView
}

type findingView struct {
	Severity      string
	Where         string
	State         string
	EvidencePtr   string
	CounterRefute string
	StopsAt       string
}

// Counts is the summary strip.
type Counts struct {
	Goals, Intents, Facts, Findings, Hints, Assets int
	Todo, Done, NeedsApproval, Active              int
}

type pageData struct {
	Title       string
	GeneratedAt string
	Counts      Counts
	Goals       []string
	Nodes       []nodeView
	OpenDoors   []nodeView
}

// Render produces the HTML document.
func Render(g *graph.Graph, opts Options) ([]byte, error) {
	if opts.Title == "" {
		opts.Title = "youkai exploration timeline"
	}
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	if opts.MaxStatementChars <= 0 {
		opts.MaxStatementChars = 600
	}
	if g == nil {
		g = graph.New()
	}

	data := pageData{
		Title:       opts.Title,
		GeneratedAt: opts.GeneratedAt.Format(time.RFC3339),
	}

	sorted := make([]*graph.Node, len(g.Nodes))
	copy(sorted, g.Nodes)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})

	for _, n := range sorted {
		switch n.Kind {
		case graph.KindGoal:
			data.Counts.Goals++
			data.Goals = append(data.Goals, truncate(n.String("statement"), opts.MaxStatementChars))
		case graph.KindIntent:
			data.Counts.Intents++
			switch n.Status() {
			case graph.StatusDone:
				data.Counts.Done++
			case graph.StatusNeedsApproval:
				data.Counts.NeedsApproval++
			case graph.StatusActive:
				data.Counts.Active++
			default:
				data.Counts.Todo++
			}
		case graph.KindFact:
			data.Counts.Facts++
		case graph.KindFinding:
			data.Counts.Findings++
		case graph.KindHint:
			data.Counts.Hints++
		case graph.KindAsset:
			data.Counts.Assets++
		}

		v := renderNode(g, n, opts)
		data.Nodes = append(data.Nodes, v)
		if n.Kind == graph.KindIntent && n.Status() == graph.StatusNeedsApproval {
			data.OpenDoors = append(data.OpenDoors, v)
		}
	}

	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func renderNode(g *graph.Graph, n *graph.Node, opts Options) nodeView {
	v := nodeView{
		ID:        n.ID,
		Kind:      string(n.Kind),
		Time:      n.CreatedAt.Format("2006-01-02 15:04:05Z"),
		Status:    n.Status(),
		Tier:      n.Int("tier"),
		Tags:      n.Strings("tags"),
		Anchors:   g.Anchors(n.ID),
		Relations: relations(g, n.ID),
	}

	switch n.Kind {
	case graph.KindGoal:
		v.Title = truncate(n.String("statement"), opts.MaxStatementChars)
		v.Subtitle = "goal"
	case graph.KindIntent:
		v.Title = n.String("action")
		v.Subtitle = compactJSON(n.Map("args"), opts.MaxStatementChars)
		v.Detail = truncate(n.String("rationale"), opts.MaxStatementChars)
		if n.Bool("inferred") {
			v.Evidence = append(v.Evidence, "inferred by the LLM planner; archive: "+n.String("provenance"))
		}
		if tr := n.String("trace"); tr != "" {
			v.Evidence = append(v.Evidence, truncate(tr, opts.MaxStatementChars))
		}
	case graph.KindFact:
		v.Title = truncate(n.String("statement"), opts.MaxStatementChars)
		if m, ok := n.Prop("evidence").(map[string]any); ok {
			for _, k := range sortedKeys(m) {
				if isSensitiveKey(k) {
					continue
				}
				v.Evidence = append(v.Evidence, k+"="+truncate(scalar(m[k]), 200))
			}
		}
	case graph.KindFinding:
		v.Title = truncate(n.String("title"), opts.MaxStatementChars)
		v.Subtitle = truncate(n.String("where"), 300)
		v.Detail = truncate(n.String("detail"), opts.MaxStatementChars)
		state := n.String("status")
		if state == "" {
			state = "candidate"
		}
		ptr := ""
		if m, ok := n.Prop("evidence").(map[string]any); ok {
			if id, ok := m["request_id"].(string); ok {
				ptr = "request_id=" + id
			}
		}
		v.Finding = &findingView{
			Severity:      n.String("severity"),
			Where:         truncate(n.String("where"), 300),
			State:         state,
			EvidencePtr:   orNone(ptr),
			CounterRefute: orNone(truncate(n.String("refutation"), 300)),
			StopsAt:       orNone(truncate(n.String("stop_condition"), 300)),
		}
	case graph.KindHint:
		v.Title = truncate(n.String("note"), opts.MaxStatementChars)
		v.Subtitle = n.String("source")
		if hs := n.Strings("hosts"); len(hs) > 0 {
			v.Evidence = append(v.Evidence, "bootstrap hosts: "+strings.Join(hs, ", "))
		}
	case graph.KindAsset:
		v.Title = n.String("value")
		kind := n.String("kind")
		sub := ""
		if kind != "" {
			sub = "kind=" + kind
		}
		if b := n.String("base"); b != "" {
			sub = strings.TrimSpace(sub + " base=" + b)
		}
		v.Subtitle = sub
	}
	if v.Title == "" {
		v.Title = "(empty " + string(n.Kind) + ")"
	}
	return v
}

func relations(g *graph.Graph, id int64) []string {
	var out []string
	for _, e := range g.Edges {
		switch {
		case e.From == id:
			out = append(out, e.Rel+" -> #"+itoa(e.To))
		case e.To == id:
			out = append(out, e.Rel+" <- #"+itoa(e.From))
		}
	}
	sort.Strings(out)
	return out
}

// isSensitiveKey keeps credential-shaped props out of the page even if something
// upstream accidentally recorded them.
func isSensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, bad := range []string{"password", "passwd", "secret", "token", "cookie", "authorization", "api_key", "apikey", "session"} {
		if strings.Contains(k, bad) {
			return true
		}
	}
	return false
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return compactJSON(t, 200)
	}
}

func compactJSON(v any, max int) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return truncate(string(b), max)
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

var pageTemplate = template.Must(template.New("timeline").Parse(`<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{color-scheme:light dark;--fg:#1a1a1a;--bg:#fbfbf9;--muted:#6b6b6b;--line:#dcdcd6;--card:#fff;--accent:#2f6f4f;--warn:#a3541c}
@media (prefers-color-scheme:dark){:root{--fg:#e8e8e4;--bg:#161614;--muted:#9a9a94;--line:#33332f;--card:#1e1e1b;--accent:#6fbf95;--warn:#e0a063}}
body{margin:0;padding:2rem;background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans SC",sans-serif}
h1{font-size:1.35rem;margin:0 0 .25rem}
.meta{color:var(--muted);font-size:.85rem;margin-bottom:1.5rem}
.counts{display:flex;flex-wrap:wrap;gap:.5rem;margin:0 0 1.5rem;padding:0;list-style:none}
.counts li{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.35rem .6rem;font-size:.85rem}
.counts b{color:var(--accent)}
section{margin:0 0 2rem}
h2{font-size:1rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);border-bottom:1px solid var(--line);padding-bottom:.35rem}
ol.timeline{list-style:none;margin:0;padding:0}
ol.timeline li{position:relative;border-left:2px solid var(--line);padding:.6rem 0 .6rem 1rem;margin-left:.4rem}
ol.timeline li:before{content:"";position:absolute;left:-6px;top:1.05rem;width:10px;height:10px;border-radius:50%;background:var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.6rem .8rem}
.head{display:flex;gap:.5rem;align-items:baseline;flex-wrap:wrap}
.id{color:var(--muted);font-variant-numeric:tabular-nums;font-size:.8rem}
.kind{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;border:1px solid var(--line);border-radius:4px;padding:.05rem .35rem;color:var(--muted)}
.title{font-weight:600}
.sub{color:var(--muted);font-size:.85rem;word-break:break-all}
.detail{margin:.35rem 0 0;white-space:pre-wrap;word-break:break-word}
dl{margin:.4rem 0 0;display:grid;grid-template-columns:max-content 1fr;gap:.15rem .6rem;font-size:.85rem}
dt{color:var(--muted)}
dd{margin:0;word-break:break-word}
.tag{display:inline-block;border:1px solid var(--line);border-radius:4px;padding:0 .3rem;margin-right:.25rem;font-size:.75rem;color:var(--muted)}
.status-needs_approval{color:var(--warn);font-weight:600}
.status-verified{color:var(--accent);font-weight:600}
.status-candidate{color:var(--warn)}
.door{border-color:var(--warn)}
footer{color:var(--muted);font-size:.8rem;border-top:1px solid var(--line);padding-top:1rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}
</style>
</head>
<body>
<h1>{{.Title}}</h1>
<p class="meta">generated {{.GeneratedAt}} · self-contained read-only snapshot · no response bodies, no credentials</p>
<ul class="counts">
<li>goal <b>{{.Counts.Goals}}</b></li>
<li>intent <b>{{.Counts.Intents}}</b> (todo {{.Counts.Todo}}, active {{.Counts.Active}}, done {{.Counts.Done}})</li>
<li>fact <b>{{.Counts.Facts}}</b></li>
<li>finding <b>{{.Counts.Findings}}</b></li>
<li>asset <b>{{.Counts.Assets}}</b></li>
<li>hint <b>{{.Counts.Hints}}</b></li>
<li>needs approval <b>{{.Counts.NeedsApproval}}</b></li>
</ul>

{{if .Goals}}
<section>
<h2>Goal</h2>
{{range .Goals}}<p>{{.}}</p>{{end}}
</section>
{{end}}

{{if .OpenDoors}}
<section>
<h2>Stopped at the door (needs a human)</h2>
{{range .OpenDoors}}
<div class="card door">
<div class="head"><span class="id">#{{.ID}}</span><span class="kind">{{.Kind}}</span><span class="title">{{.Title}}</span><span class="status-needs_approval">needs_approval · tier {{.Tier}}</span></div>
<div class="sub">{{.Subtitle}}</div>
<p>youkai does not approve or execute tier&gt;=2. Run this one action through Fairy with high-auth plus a single confirm, then ingest the result back.</p>
</div>
{{end}}
</section>
{{end}}

<section>
<h2>Timeline (append-only, in creation order)</h2>
<ol class="timeline">
{{range .Nodes}}
<li>
<div class="card">
<div class="head"><span class="id">#{{.ID}}</span><span class="kind">{{.Kind}}</span><span class="title">{{.Title}}</span>
{{if eq .Kind "intent"}}<span class="status-{{.Status}}">{{.Status}} · tier {{.Tier}}</span>{{end}}
</div>
{{if .Subtitle}}<div class="sub">{{.Subtitle}}</div>{{end}}
{{if .Detail}}<div class="detail">{{.Detail}}</div>{{end}}
{{if .Tags}}<div>{{range .Tags}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}
{{if .Finding}}
<dl>
<dt>state</dt><dd class="status-{{.Finding.State}}">{{.Finding.State}}</dd>
<dt>severity</dt><dd>{{.Finding.Severity}}</dd>
<dt>where</dt><dd>{{.Finding.Where}}</dd>
<dt>evidence</dt><dd>{{.Finding.EvidencePtr}}</dd>
<dt>counter-evidence</dt><dd>{{.Finding.CounterRefute}}</dd>
<dt>stop condition</dt><dd>{{.Finding.StopsAt}}</dd>
</dl>
{{end}}
{{if .Anchors}}<dl><dt>anchors</dt><dd>{{range .Anchors}}<code>{{.}}</code> {{end}}</dd></dl>{{end}}
{{if .Relations}}<dl><dt>lineage</dt><dd>{{range .Relations}}<code>{{.}}</code> {{end}}</dd></dl>{{end}}
{{if .Evidence}}<dl><dt>trace</dt><dd>{{range .Evidence}}<div>{{.}}</div>{{end}}</dd></dl>{{end}}
<div class="sub">created {{.Time}}</div>
</div>
</li>
{{end}}
</ol>
</section>

<footer>youkai — a brain with no direct reach. Every target-facing action in this graph was performed by a hand (Fairy / Verdex) under its own authorisation; findings stay candidates until an operator confirms them.</footer>
</body>
</html>
`))
