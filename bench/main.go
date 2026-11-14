// Command bench measures youkai against a local lab target.
//
// It is deliberately an in-process harness: it opens the ledger, starts the engine,
// and lets the real dispatcher (and therefore the real guard) do the work. There is
// no HTTP client in here and no second way to reach the target - the number this
// reports is produced by the same code path production uses.
//
// What it measures, and what it does not:
//
//   - recall / precision against a ground truth that is a property of the lab
//     source (scripts/lab-target.py deliberately serves /.git/config, reflects a
//     parameter, omits security headers and exposes its stack version);
//   - request cost per finding, from the audit log;
//   - out-of-scope requests, which must be zero.
//
// The tier-2 capabilities are NOT exercised: they require a human approval and a
// signed high-authorisation record by design, and a benchmark that fakes those
// would be measuring a different product. So these numbers describe the autonomous
// read-only chain only. They are numbers for THIS lab on THIS machine; they are not
// a claim about any other target.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"youkai/internal/engine"
	"youkai/internal/ledger"
	"youkai/internal/runtime"
)

func main() {
	dsn := flag.String("dsn", envOr("YOUKAI_BENCH_DSN",
		"postgres://youkai:youkai_dev_pw@127.0.0.1:55432/youkai_test?sslmode=disable"),
		"PostgreSQL DSN (a throwaway database; the bench writes an engagement into it)")
	port := flag.Int("port", 18086, "port for the lab target")
	steps := flag.Int("max-steps", 12, "autonomous step budget")
	outDir := flag.String("out", "bench/results", "where the JSON result is written")
	keep := flag.Bool("keep", false, "keep the engagement after the run (for inspection)")
	flag.Parse()

	if err := run(*dsn, *port, *steps, *outDir, *keep); err != nil {
		fmt.Fprintln(os.Stderr, "bench: "+err.Error())
		os.Exit(1)
	}
}

type result struct {
	Schema     string     `json:"schema"`
	Lab        string     `json:"lab"`
	Target     string     `json:"target"`
	Steps      int        `json:"max_steps"`
	RanAt      string     `json:"ran_at"`
	Recall     float64    `json:"recall"`
	Precision  float64    `json:"precision"`
	Truth      []truthHit `json:"ground_truth"`
	Findings   int        `json:"findings"`
	Requests   int        `json:"requests_allowed"`
	Blocked    int        `json:"requests_blocked"`
	CostPerHit float64    `json:"requests_per_finding"`
	// EgressOK is the one hard assertion: an authorised lab run must never produce
	// an out-of-scope request.
	EgressOK bool   `json:"egress_zero"`
	Stop     string `json:"stop_reason"`
	Note     string `json:"note"`
}

type truthHit struct {
	Key      string `json:"key"`
	Expected string `json:"expected"`
	Found    bool   `json:"found"`
	Finding  string `json:"finding,omitempty"`
}

// groundTruth is derived from scripts/lab-target.py, not from a previous youkai run:
// each entry is something the lab source demonstrably does.
func groundTruth() []struct {
	Key, Expected, Kind, WhereHas, TitleHas string
} {
	return []struct{ Key, Expected, Kind, WhereHas, TitleHas string }{
		{"git-exposure", "仓库配置可读 (/.git/config 返回 200 且含 [core])", "exposure", "/.git/config", ""},
		{"reflection", "参数 q 反射进响应", "reflection", "/search", ""},
		{"header-csp", "缺失 CSP", "header-missing", "/search", "CSP"},
		{"header-xfo", "缺失 X-Frame-Options", "header-missing", "/search", "X-Frame-Options"},
		{"header-xcto", "缺失 X-Content-Type-Options", "header-missing", "/search", "X-Content-Type-Options"},
		{"header-referrer", "缺失 Referrer-Policy", "header-missing", "/search", "Referrer-Policy"},
		{"version", "服务端版本号暴露", "version-disclosure", "/search", ""},
		{"api-doc", "API 文档可公开读取", "exposure", "/openapi.json", ""},
	}
}

func run(dsn string, port, maxSteps int, outDir string, keep bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 1) the lab target, as a child process (its own loopback server)
	lab := exec.Command("python", "scripts/lab-target.py", fmt.Sprint(port))
	lab.Stdout = os.Stderr
	lab.Stderr = os.Stderr
	if err := lab.Start(); err != nil {
		return fmt.Errorf("start lab target (is python on PATH?): %w", err)
	}
	defer func() { _ = lab.Process.Kill(); _, _ = lab.Process.Wait() }()
	// The harness has no HTTP client by design, so the warm-up is a short sleep. If
	// the lab is slow, the first request fails and shows up as a stop reason; the
	// bench reports that instead of inventing numbers.
	time.Sleep(1500 * time.Millisecond)

	// 2) the ledger
	store, err := ledger.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open ledger (%s): %w", dsn, err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	target := fmt.Sprintf("http://127.0.0.1:%d", port)
	eng, err := store.CreateEngagement(ctx, fmt.Sprintf("bench-%d", time.Now().Unix()),
		map[string]any{
			"project":       "youkai-lab",
			"include":       []string{fmt.Sprintf("127.0.0.1:%d", port)},
			"basis":         "youkai bench: self-hosted lab on this machine",
			"operator":      "bench",
			"allow_private": true,
			"max_requests":  500,
			"rps":           20,
		})
	if err != nil {
		return fmt.Errorf("create engagement: %w", err)
	}
	if !keep {
		// The bench writes into a throwaway database, but it still cleans up after
		// itself: an engagement left behind would show up in someone else's UI.
		defer func() {
			del, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = store.Pool().Exec(del, `DELETE FROM engagements WHERE id = $1`, eng.ID)
		}()
	}

	// 3) the real dispatcher and engine: the guard is in the path, as in production
	disp := runtime.New(store, filepath.Join(os.TempDir(), "youkai-bench-artifacts"))
	seed := target + "/search?q=bench"
	// The engine derives its first surfaces from SeedURLs, exactly as youkaid does
	// when it starts a run; without it a bare "host:port" passport defaults to https.
	e, err := engine.New(engine.Config{
		Store:        store,
		Dispatcher:   disp,
		EngagementID: eng.ID,
		Engagement:   eng.Name,
		MaxSteps:     maxSteps,
		SeedURLs:     []string{seed},
	})
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}
	runRow, err := store.CreateRun(ctx, eng.ID, map[string]any{
		"seed_urls": []string{seed}, "max_steps": maxSteps, "trigger": "bench",
	})
	if err != nil {
		return fmt.Errorf("create run: %w", err)
	}
	rep, err := e.Run(ctx, runRow.ID)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	if err := store.FinishRun(ctx, runRow.ID, rep.Stop, rep.Reason, len(rep.Steps), rep.Derived); err != nil {
		return fmt.Errorf("finish run: %w", err)
	}

	// 4) measure what the ledger says happened
	g, err := store.Graph(ctx, eng.ID)
	if err != nil {
		return err
	}
	audit, err := store.AuditTail(ctx, eng.Name, 2000)
	if err != nil {
		return err
	}

	res := result{
		Schema:   "YoukaiBench/v1",
		Lab:      "scripts/lab-target.py",
		Target:   target,
		Steps:    maxSteps,
		RanAt:    time.Now().UTC().Format(time.RFC3339),
		Findings: len(g.Findings),
		Stop:     rep.Stop + " — " + rep.Reason,
		Note:     "本机靶场、匿名只读链(档 1)的测量；档 2 需要人批,不在基准内;数字不外推。",
	}
	allowed, blocked := 0, 0
	for _, a := range audit {
		switch a.Verdict {
		case "allowed":
			allowed++
		case "blocked":
			blocked++
		}
	}
	res.Requests, res.Blocked = allowed, blocked
	res.EgressOK = blocked == 0

	matched := 0
	for _, t := range groundTruth() {
		hit := truthHit{Key: t.Key, Expected: t.Expected}
		for _, f := range g.Findings {
			if f.Kind != t.Kind {
				continue
			}
			if t.WhereHas != "" && !containsFold(f.Where, t.WhereHas) {
				continue
			}
			if t.TitleHas != "" && !containsFold(f.Title, t.TitleHas) {
				continue
			}
			hit.Found = true
			hit.Finding = fmt.Sprintf("#%d %s", f.ID, f.Title)
			break
		}
		if hit.Found {
			matched++
		}
		res.Truth = append(res.Truth, hit)
	}

	if n := len(res.Truth); n > 0 {
		res.Recall = round(float64(matched)/float64(n), 3)
	}
	// Precision is judged at the CLASS level: a finding counts as true when its kind
	// is one of the classes this lab is known to exhibit. That is the honest question
	// for a scanner on a lab - "did it invent something that is not there?" - because
	// the same missing header will legitimately be reported once per endpoint, and
	// treating those repeats as false positives would measure cataloguing noise.
	// Recall above stays per-entry: did we find each declared issue.
	truePos := 0
	for _, f := range g.Findings {
		for _, t := range groundTruth() {
			if f.Kind == t.Kind {
				truePos++
				break
			}
		}
	}
	if len(g.Findings) > 0 {
		res.Precision = round(float64(truePos)/float64(len(g.Findings)), 3)
	}
	if matched > 0 {
		res.CostPerHit = round(float64(allowed)/float64(matched), 2)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(outDir, time.Now().UTC().Format("2006-01-02")+".json")
	raw, _ := json.MarshalIndent(res, "", "  ")
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		return err
	}

	fmt.Printf("youkai bench · %s · steps=%d\n", target, maxSteps)
	fmt.Printf("  recall %.3f  precision %.3f  findings %d  requests %d (blocked %d)  cost/finding %.2f\n",
		res.Recall, res.Precision, res.Findings, res.Requests, res.Blocked, res.CostPerHit)
	for _, t := range res.Truth {
		mark := "MISS"
		if t.Found {
			mark = "ok  "
		}
		fmt.Printf("  %s %-16s %s\n", mark, t.Key, t.Expected)
	}
	fmt.Printf("  stop: %s\n", res.Stop)
	fmt.Printf("  wrote %s\n", path)
	if !res.EgressOK {
		return fmt.Errorf("%d out-of-scope request(s) — the hard assertion failed", res.Blocked)
	}
	return nil
}

func containsFold(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexFold(haystack, needle) >= 0)
}

func indexFold(s, sub string) int {
	ls, lsub := []byte(s), []byte(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if equalFold(ls[i:i+len(lsub)], lsub) {
			return i
		}
	}
	return -1
}

func equalFold(a, b []byte) bool {
	for i := range a {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func round(v float64, places int) float64 {
	pow := 1.0
	for i := 0; i < places; i++ {
		pow *= 10
	}
	return float64(int(v*pow+0.5)) / pow
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
