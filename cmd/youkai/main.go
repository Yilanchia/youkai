// Command youkai is the brain: a bounded, append-only exploration loop that
// drives two hands (Fairy for web, Verdex for binaries) and stops in front of
// anything proof-grade.
//
// Quick start:
//
//	youkai init --fairy-dir D:\fairy_fairy --verdex-dir D:\漏洞挖掘工作台
//	youkai hands
//	youkai run --project lab-demo --seed http://127.0.0.1:8080
//	youkai html --out youkai-timeline.html
//	youkai step propose --next --project lab-demo
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"youkai/internal/gate"
	"youkai/internal/graph"
	"youkai/internal/hands"
	"youkai/internal/loop"
	"youkai/internal/mcp"
	"youkai/internal/planner"
	"youkai/internal/step"
	"youkai/internal/timeline"
)

// Exit codes, so a wrapper script can tell a stop from a failure.
const (
	exitOK            = 0
	exitError         = 1
	exitUsage         = 2
	exitNeedsApproval = 10
	exitSensitive     = 11
)

const version = "0.1.0"

// exitCode is an error that a command can return to pick a specific exit status
// without printing a redundant message.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "hands":
		err = cmdHands(args)
	case "run":
		err = cmdRun(args)
	case "graph":
		err = cmdGraph(args)
	case "html":
		err = cmdHTML(args)
	case "intent":
		err = cmdIntent(args)
	case "step":
		err = cmdStep(args)
	case "version", "-v", "--version":
		fmt.Println("youkai " + version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "youkai: unknown command %q\n\n", cmd)
		usage()
		os.Exit(exitUsage)
	}
	if err == nil {
		return
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	var code exitCode
	if errors.As(err, &code) {
		os.Exit(int(code))
	}
	fmt.Fprintln(os.Stderr, "youkai: "+err.Error())
	os.Exit(exitError)
}

func usage() {
	fmt.Fprint(os.Stderr, `youkai `+version+` - read-only evidence brain for authorised engagements

USAGE
  youkai <command> [flags]

COMMANDS
  init      write .youkai/hands.json (where the two hands live)
  hands     connect the hands and print their tool inventory (doctor)
  run       run the bounded exploration loop (tier 1 only)
  graph     print the exploration graph summary or raw JSON
  html      render the graph as a self-contained read-only page
  intent    inspect / seed / update intents (youkai never approves)
  step      human-in-loop stepping mode for ONE tier-2 action at a time
  version   print the version

THE RULES YOU CANNOT FLAG AWAY
  * the loop only executes tier 1 (read-only). It stops at needs_approval before
    anything proof-grade and hands it to a human.
  * youkai never approves, never executes tier 3, never upgrades candidate to
    verified, and never retries a failed action.
  * every conclusion carries a request_id (or file:line) plus an audit location.
  * the OSS build has no exploitation provider: gate.Provider().Available()==false.

EXIT CODES
  0 ok   1 error   2 usage   10 stopped at needs_approval   11 sensitive data stop
`)
}

// ---- shared plumbing -------------------------------------------------------

type common struct {
	workspace string
	project   string
}

func (c common) handsPath() string  { return filepath.Join(c.workspace, hands.DefaultConfigPath) }
func (c common) graphPath() string  { return filepath.Join(c.workspace, ".youkai", "explore.json") }
func (c common) stepPath() string   { return filepath.Join(c.workspace, step.DefaultStatePath) }
func (c common) plannerDir() string { return filepath.Join(c.workspace, ".youkai", "planner") }

func addCommonFlags(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.workspace, "workspace", ".", "workspace root (holds .youkai/)")
	fs.StringVar(&c.project, "project", "", "Fairy engagement directory (sent with every Fairy call)")
	return c
}

func (c common) dial(ctx context.Context) (*hands.Set, error) {
	cfg, err := hands.LoadConfig(c.handsPath())
	if err != nil {
		return nil, fmt.Errorf("%w (run `youkai init` first)", err)
	}
	return hands.Dial(ctx, cfg)
}

func (c common) openGraph() (*graph.Owner, error) {
	return graph.Open(c.graphPath())
}

// ---- init ------------------------------------------------------------------

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	c := addCommonFlags(fs)
	fairyDir := fs.String("fairy-dir", `D:\fairy_fairy`, "Fairy checkout")
	verdexDir := fs.String("verdex-dir", `D:\漏洞挖掘工作台`, "Verdex checkout")
	fairyCmd := fs.String("fairy-cmd", "node", "interpreter for the Fairy hand")
	verdexCmd := fs.String("verdex-cmd", "node", "interpreter for the Verdex hand")
	force := fs.Bool("force", false, "overwrite an existing hands.json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := c.handsPath()
	if _, err := os.Stat(path); err == nil && !*force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", path)
	}

	cfg := hands.Config{
		Fairy: mcp.HandConfig{
			Cwd: *fairyDir, Cmd: *fairyCmd, Args: []string{"src/cli.js", "mcp"},
		},
		Verdex: mcp.HandConfig{
			Cwd: *verdexDir, Cmd: *verdexCmd, Args: []string{"bin/verdex-mcp.mjs"},
		},
	}
	if err := hands.SaveConfig(path, cfg); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n  fairy  cwd=%s\n  verdex cwd=%s\n", path, cfg.Fairy.Cwd, cfg.Verdex.Cwd)
	fmt.Println("next: youkai hands")
	return nil
}

// ---- hands doctor ----------------------------------------------------------

func cmdHands(args []string) error {
	fs := flag.NewFlagSet("hands", flag.ExitOnError)
	c := addCommonFlags(fs)
	all := fs.Bool("all", false, "print every tool name")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()

	set, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer set.Close()

	for _, name := range set.Hands() {
		info, _ := set.ServerInfo(name)
		tools := set.ToolNames(name)
		fmt.Printf("%s: %s v%s, %d tools, protocol %s\n",
			name, info.ServerInfo.Name, info.ServerInfo.Version, len(tools), info.ProtocolVersion)
		if *all {
			for _, t := range tools {
				fmt.Println("  - " + t)
			}
			continue
		}
		for _, want := range requiredTools(name) {
			mark := "MISSING"
			if contains(tools, want) {
				mark = "ok"
			}
			fmt.Printf("  %-8s %s\n", mark, want)
		}
	}
	fmt.Printf("\nexploitation provider: %s (available=%v)\n",
		gate.Provider().Reason(), gate.Provider().Available())
	return nil
}

func requiredTools(hand string) []string {
	if hand == hands.Fairy {
		return []string{"fairy_scope_init", "fairy_planner_tick", "fairy_ledger_show", "web_probe", "web_scan", "fairy_ingest", "fairy_handoff"}
	}
	return []string{"analyze_target", "bin_info", "bin_decompile"}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// ---- run -------------------------------------------------------------------

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	c := addCommonFlags(fs)
	seed := fs.String("seed", "", "comma-separated base URLs to bootstrap when the ledger is empty")
	maxSteps := fs.Int("max-steps", 10, "hard step budget for this run")
	concurrency := fs.Int("concurrency", 3, "worker pool size")
	debounce := fs.Duration("debounce", 0, "coalesce graph-change signals (e.g. 200ms)")
	useLLM := fs.Bool("llm", false, "enable the optional LLM planner (needs YOUKAI_LLM_BASE_URL/_MODEL)")
	jsonOut := fs.Bool("json", false, "print the full report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(c.project) == "" {
		return fmt.Errorf("--project is required (Fairy needs an engagement directory)")
	}

	ctx, stop := signalContext()
	defer stop()

	owner, err := c.openGraph()
	if err != nil {
		return err
	}
	defer owner.Close()

	set, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer set.Close()

	cfg := loop.Config{
		Project:      c.project,
		SeedHosts:    splitList(*seed),
		MaxSteps:     *maxSteps,
		Concurrency:  *concurrency,
		Debounce:     *debounce,
		AllowedTools: planner.DefaultAllowedTools(),
	}
	if *useLLM {
		pcfg, ok := planner.FromEnv()
		if !ok {
			return fmt.Errorf("--llm needs both %s and %s", planner.EnvBaseURL, planner.EnvModel)
		}
		pcfg.ArchiveDir = c.plannerDir()
		p, err := planner.New(pcfg)
		if err != nil {
			return err
		}
		cfg.Proposer = p
		fmt.Printf("llm planner enabled: model=%s archive=%s\n", pcfg.Model, pcfg.ArchiveDir)
	}

	runner, err := loop.New(cfg, owner, set)
	if err != nil {
		return err
	}
	rep, err := runner.Run(ctx)
	if err != nil {
		return err
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printReport(rep, c.project)
	}

	switch rep.Stop {
	case loop.StopNeedsApproval:
		return exitCode(exitNeedsApproval)
	case loop.StopSensitive:
		return exitCode(exitSensitive)
	}
	return nil
}

func printReport(rep loop.Report, project string) {
	fmt.Printf("stop: %s\n", rep.Stop)
	if rep.Reason != "" {
		fmt.Printf("reason: %s\n", rep.Reason)
	}
	fmt.Printf("derived intents: %d, executed steps: %d\n", rep.Derived, len(rep.Steps))
	fmt.Printf("exploitation provider: %s\n", rep.ExploitProvider)
	if len(rep.Steps) > 0 {
		fmt.Println()
	}
	for _, s := range rep.Steps {
		status := "ok"
		if !s.OK {
			status = "FAILED"
		}
		fmt.Printf("  #%d %-14s tier %d via %-6s %s facts=%d findings=%d",
			s.IntentID, s.Action, s.Tier, s.Hand, status, s.Facts, s.Findings)
		if s.RequestID != "" {
			fmt.Printf(" request_id=%s", s.RequestID)
		}
		if s.AuditPath != "" {
			fmt.Printf(" audit=%s", s.AuditPath)
		}
		if s.Err != "" {
			fmt.Printf(" err=%s", s.Err)
		}
		fmt.Println()
	}

	if len(rep.Pending) == 0 {
		return
	}
	fmt.Printf("\nSTOPPED AT THE DOOR - %d intent(s) need a human:\n", len(rep.Pending))
	for _, p := range rep.Pending {
		fmt.Printf("\n  intent #%d  %s  (tier %d)\n", p.IntentID, p.Action, p.Tier)
		fmt.Printf("    exact request : %s\n", p.ExactRequest)
		fmt.Printf("    min impact    : %s\n", p.MinImpact)
		fmt.Printf("    stop condition: %s\n", p.StopCondition)
		fmt.Printf("    why it stopped: %s\n", p.Reason)
		for _, e := range p.Evidence {
			fmt.Printf("    evidence      : %s\n", e)
		}
		fmt.Printf("    how to proceed: %s\n", p.HowToApprove)
	}
	fmt.Printf("\nnext: youkai step propose --next --project %s\n", project)
}

// ---- graph / html ----------------------------------------------------------

func cmdGraph(args []string) error {
	fs := flag.NewFlagSet("graph", flag.ExitOnError)
	c := addCommonFlags(fs)
	asJSON := fs.Bool("json", false, "dump the whole graph as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	owner, err := c.openGraph()
	if err != nil {
		return err
	}
	defer owner.Close()
	g := owner.Snapshot()

	if *asJSON {
		b, err := json.MarshalIndent(g, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	printGraphSummary(g)
	return nil
}

func printGraphSummary(g *graph.Graph) {
	counts := map[graph.Kind]int{}
	for _, n := range g.Nodes {
		counts[n.Kind]++
	}
	fmt.Printf("log seq: %d (append-only, replayable)\n", g.Seq)
	fmt.Printf("nodes: goal=%d intent=%d fact=%d finding=%d asset=%d hint=%d  edges=%d\n",
		counts[graph.KindGoal], counts[graph.KindIntent], counts[graph.KindFact],
		counts[graph.KindFinding], counts[graph.KindAsset], counts[graph.KindHint], len(g.Edges))
	fmt.Println()
	for _, n := range g.OfKind(graph.KindIntent) {
		mark := "  "
		if n.Status() == graph.StatusNeedsApproval {
			mark = "->"
		}
		fmt.Printf("%s #%-3d %-16s tier %d  %-14s %s\n",
			mark, n.ID, n.String("action"), n.Int("tier"), n.Status(), argsPreview(n.Map("args")))
	}
	for _, n := range g.OfKind(graph.KindFact) {
		fmt.Printf("   #%-3d fact  %s\n", n.ID, n.String("statement"))
	}
	for _, n := range g.OfKind(graph.KindFinding) {
		fmt.Printf("   #%-3d finding [%s] %s @ %s\n", n.ID, findingState(n), n.String("title"), n.String("where"))
	}
}

// findingState defaults to the only honest starting state for a candidate.
func findingState(n *graph.Node) string {
	if s := n.String("status"); s != "" {
		return s
	}
	return "candidate"
}

func argsPreview(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	b, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	s := string(b)
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

func cmdHTML(args []string) error {
	fs := flag.NewFlagSet("html", flag.ExitOnError)
	c := addCommonFlags(fs)
	out := fs.String("out", "youkai-timeline.html", "output path")
	title := fs.String("title", "", "page title (defaults to the project name)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	owner, err := c.openGraph()
	if err != nil {
		return err
	}
	defer owner.Close()

	if *title == "" {
		*title = "youkai exploration timeline"
		if c.project != "" {
			*title = "youkai - " + c.project
		}
	}
	page, err := timeline.Render(owner.Snapshot(), timeline.Options{Title: *title})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, page, 0o644); err != nil {
		return err
	}
	abs, _ := filepath.Abs(*out)
	fmt.Printf("wrote %s (%d bytes, self-contained, read-only)\n", abs, len(page))
	return nil
}

// ---- intents ---------------------------------------------------------------

func cmdIntent(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: youkai intent list|add|set [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return cmdIntentList(rest)
	case "add":
		return cmdIntentAdd(rest)
	case "set":
		return cmdIntentSet(rest)
	case "approve":
		// Deliberately absent: youkai never approves, in any tier. Approvals go
		// through Fairy's high-auth path, which a human holds.
		return fmt.Errorf("youkai never approves intents: use Fairy's high-auth + confirm path, then `youkai intent set --status done`")
	default:
		return fmt.Errorf("unknown intent subcommand %q", sub)
	}
}

func cmdIntentList(args []string) error {
	fs := flag.NewFlagSet("intent list", flag.ExitOnError)
	c := addCommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	owner, err := c.openGraph()
	if err != nil {
		return err
	}
	defer owner.Close()
	printGraphSummary(owner.Snapshot())
	return nil
}

func cmdIntentAdd(args []string) error {
	fs := flag.NewFlagSet("intent add", flag.ExitOnError)
	c := addCommonFlags(fs)
	action := fs.String("action", "", "tool name")
	argsJSON := fs.String("args", "{}", "tool arguments as JSON")
	rationale := fs.String("rationale", "", "why this step")
	expected := fs.String("expected", "", "what fact it should produce")
	anchor := fs.String("anchor", "", "ledger anchor value, e.g. host:lab.invalid")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*action) == "" {
		return fmt.Errorf("--action is required")
	}
	var toolArgs map[string]any
	if err := json.Unmarshal([]byte(*argsJSON), &toolArgs); err != nil {
		return fmt.Errorf("--args is not a JSON object: %w", err)
	}

	dec := gate.Explain(*action, toolArgs)
	owner, err := c.openGraph()
	if err != nil {
		return err
	}
	defer owner.Close()

	props := map[string]any{
		"action":            *action,
		"args":              toolArgs,
		"tier":              int(dec.Tier),
		"tier_reason":       dec.Reason,
		"requires_approval": dec.Tier.NeedsHuman(),
		"status":            graph.StatusTodo,
	}
	if *rationale != "" {
		props["rationale"] = *rationale
	}
	if *expected != "" {
		props["expected_fact"] = *expected
	}
	var anchors []string
	if *anchor != "" {
		anchors = []string{*anchor}
	}
	res, err := owner.Apply(graph.CmdAddNode(graph.NodeSeed{Kind: graph.KindIntent, Props: props, Anchors: anchors}))
	if err != nil {
		return err
	}
	fmt.Printf("added intent #%d: %s tier=%d (%s)\n", res.NodeID, *action, dec.Tier, dec.Reason)
	if dec.Tier.NeedsHuman() {
		fmt.Println("this intent is proof-grade: the loop will stop in front of it, never execute it")
	}
	return nil
}

func cmdIntentSet(args []string) error {
	fs := flag.NewFlagSet("intent set", flag.ExitOnError)
	c := addCommonFlags(fs)
	id := fs.Int64("id", 0, "intent node id")
	status := fs.String("status", "", "todo|active|done|skipped|blocked|needs_approval")
	note := fs.String("note", "", "trace note")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == 0 {
		return fmt.Errorf("--id is required")
	}
	switch *status {
	case graph.StatusTodo, graph.StatusActive, graph.StatusDone, graph.StatusSkipped, graph.StatusBlocked, graph.StatusNeedsApproval:
	case "":
		return fmt.Errorf("--status is required")
	default:
		return fmt.Errorf("unknown status %q", *status)
	}

	owner, err := c.openGraph()
	if err != nil {
		return err
	}
	defer owner.Close()

	if _, err := owner.Apply(graph.CmdSetStatus(*id, *status)); err != nil {
		return err
	}
	if *note != "" {
		if _, err := owner.Apply(graph.CmdAddTrace(*id, "operator: "+*note)); err != nil {
			return err
		}
	}
	fmt.Printf("intent #%d -> %s\n", *id, *status)
	return nil
}

// ---- step ------------------------------------------------------------------

func cmdStep(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: youkai step propose|approve|execute|verdict|status|stop [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "propose":
		return cmdStepPropose(rest)
	case "approve":
		return cmdStepApprove(rest)
	case "execute":
		return cmdStepExecute(rest)
	case "verdict":
		return cmdStepVerdict(rest)
	case "status":
		return cmdStepStatus(rest)
	case "stop":
		return cmdStepStop(rest)
	default:
		return fmt.Errorf("unknown step subcommand %q", sub)
	}
}

// stepContext opens the graph and dials the hands once, then restores the
// persisted session.
func stepContext(c *common) (context.Context, func(), *step.Session, error) {
	ctx, stop := signalContext()
	owner, err := c.openGraph()
	if err != nil {
		stop()
		return nil, nil, nil, err
	}
	set, err := c.dial(ctx)
	if err != nil {
		_ = owner.Close()
		stop()
		return nil, nil, nil, err
	}
	s, err := step.Restore(c.stepPath(), owner, set, c.project)
	if err != nil {
		_ = set.Close()
		_ = owner.Close()
		stop()
		return nil, nil, nil, err
	}
	cleanup := func() {
		_ = set.Close()
		_ = owner.Close()
		stop()
	}
	return ctx, cleanup, s, nil
}

func cmdStepPropose(args []string) error {
	fs := flag.NewFlagSet("step propose", flag.ExitOnError)
	c := addCommonFlags(fs)
	next := fs.Bool("next", false, "propose the next intent parked at needs_approval")
	action := fs.String("action", "", "tool name (when not using --next)")
	argsJSON := fs.String("args", "{}", "tool arguments as JSON")
	rationale := fs.String("rationale", "", "why this step, now")
	expected := fs.String("expected", "", "what you expect to prove")
	stop := fs.String("stop", "", "when to stop (decided before running)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_, cleanup, s, err := stepContext(c)
	if err != nil {
		return err
	}
	defer cleanup()

	var p step.Proposal
	if *next {
		p, err = s.ProposeNext()
	} else {
		var toolArgs map[string]any
		if uerr := json.Unmarshal([]byte(*argsJSON), &toolArgs); uerr != nil {
			return fmt.Errorf("--args is not a JSON object: %w", uerr)
		}
		p, err = s.Propose(*action, toolArgs, *rationale, *expected, *stop)
	}
	if err != nil {
		return err
	}
	if err := s.Save(c.stepPath()); err != nil {
		return err
	}

	fmt.Printf("PROPOSAL %d (NOT executed)\n", p.Index)
	fmt.Printf("  action        : %s (tier %d)\n", p.Action, p.Tier)
	fmt.Printf("  exact request : %s\n", p.ExactRequest)
	fmt.Printf("  rationale     : %s\n", p.Rationale)
	fmt.Printf("  expected      : %s\n", p.ExpectedImpact)
	fmt.Printf("  min impact    : %s\n", p.MinImpact)
	fmt.Printf("  stop condition: %s\n", p.StopCondition)
	for _, e := range p.Evidence {
		fmt.Printf("  evidence      : %s\n", e)
	}
	fmt.Printf("\n  fingerprint   : %s\n", p.Fingerprint)
	fmt.Printf("\nRead it. If you authorise exactly this one action:\n")
	fmt.Printf("  youkai step approve --fingerprint %s --operator <you> --basis \"<why>\" --confirm\n", p.Fingerprint)
	return nil
}

func cmdStepApprove(args []string) error {
	fs := flag.NewFlagSet("step approve", flag.ExitOnError)
	c := addCommonFlags(fs)
	fingerprint := fs.String("fingerprint", "", "the fingerprint printed by `step propose`")
	operator := fs.String("operator", "", "who is authorising this")
	basis := fs.String("basis", "", "why this action is authorised")
	highAuth := fs.String("high-auth", "", "path to the Fairy high-auth record (the key stays with you)")
	confirm := fs.Bool("confirm", false, "explicit single-use confirmation for this one action")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_, cleanup, s, err := stepContext(c)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := s.Approve(step.Approval{
		Fingerprint:  *fingerprint,
		Operator:     *operator,
		Basis:        *basis,
		HighAuthPath: *highAuth,
		Confirm:      *confirm,
	}); err != nil {
		return err
	}
	if err := s.Save(c.stepPath()); err != nil {
		return err
	}
	p, _ := s.Proposal()
	fmt.Printf("approved step %d (%s) for ONE execution\n", p.Index, p.Action)
	fmt.Printf("next: youkai step execute\n")
	return nil
}

func cmdStepExecute(args []string) error {
	fs := flag.NewFlagSet("step execute", flag.ExitOnError)
	c := addCommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cleanup, s, err := stepContext(c)
	if err != nil {
		return err
	}
	defer cleanup()

	rec, execErr := s.Execute(ctx)
	saveErr := s.Save(c.stepPath())
	if execErr != nil {
		if rec.Step > 0 {
			fmt.Printf("step %d FAILED: %s\n", rec.Step, rec.Err)
		}
		return execErr
	}
	if saveErr != nil {
		return saveErr
	}
	fmt.Printf("EXECUTED step %d: %s via %s\n", rec.Step, rec.Action, rec.Hand)
	fmt.Printf("  approved by : %s (%s)\n", rec.ApprovedBy, rec.ApprovalBasis)
	fmt.Printf("  request_id  : %s\n", orNone(rec.RequestID))
	fmt.Printf("  audit path  : %s\n", orNone(rec.AuditPath))
	fmt.Println("\nthe approval is consumed. the next step needs a new proposal and a new approval.")
	return nil
}

func cmdStepVerdict(args []string) error {
	fs := flag.NewFlagSet("step verdict", flag.ExitOnError)
	c := addCommonFlags(fs)
	finding := fs.Int64("finding", 0, "finding node id")
	confirm := fs.Bool("confirm", false, "operator confirms this finding is verified")
	note := fs.String("note", "", "operator's justification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, cleanup, s, err := stepContext(c)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := s.Verdict(*finding, *confirm, *note); err != nil {
		return err
	}
	if err := s.Save(c.stepPath()); err != nil {
		return err
	}
	fmt.Printf("finding #%d -> verified (operator judgement recorded)\n", *finding)
	return nil
}

func cmdStepStatus(args []string) error {
	fs := flag.NewFlagSet("step status", flag.ExitOnError)
	c := addCommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	owner, err := c.openGraph()
	if err != nil {
		return err
	}
	defer owner.Close()
	s, err := step.Restore(c.stepPath(), owner, nil, c.project)
	if err != nil {
		return err
	}
	fmt.Printf("state: %s\n", s.State())
	if p, ok := s.Proposal(); ok {
		fmt.Printf("pending proposal %d: %s tier %d\n  %s\n  fingerprint %s\n",
			p.Index, p.Action, p.Tier, p.ExactRequest, p.Fingerprint)
	}
	for _, r := range s.Records() {
		fmt.Printf("  step %d %s ok=%v request_id=%s approved_by=%s\n",
			r.Step, r.Action, r.OK, orNone(r.RequestID), r.ApprovedBy)
	}
	return nil
}

func cmdStepStop(args []string) error {
	fs := flag.NewFlagSet("step stop", flag.ExitOnError)
	c := addCommonFlags(fs)
	reason := fs.String("reason", "operator ended the chain", "why the chain stops")
	if err := fs.Parse(args); err != nil {
		return err
	}
	owner, err := c.openGraph()
	if err != nil {
		return err
	}
	defer owner.Close()
	s, err := step.Restore(c.stepPath(), owner, nil, c.project)
	if err != nil {
		return err
	}
	s.Stop(*reason)
	if err := s.Save(c.stepPath()); err != nil {
		return err
	}
	fmt.Printf("stopped: %s\n", *reason)
	return nil
}

// ---- misc ------------------------------------------------------------------

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// signalContext cancels on Ctrl-C so a run stops cleanly and the append-only log
// stays consistent.
func signalContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		fmt.Fprintln(os.Stderr, "\ninterrupted: stopping after the current step")
		cancel()
	}()
	return ctx, func() {
		signal.Stop(ch)
		cancel()
	}
}
