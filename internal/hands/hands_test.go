package hands

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"youkai/internal/mcp"
)

// realHandsConfig points at the two hands as they are installed on this machine.
// Overridable so the test is not tied to one workstation.
func realHandsConfig() Config {
	fairy := os.Getenv("YOUKAI_FAIRY_DIR")
	if fairy == "" {
		fairy = `D:\fairy_fairy`
	}
	verdex := os.Getenv("YOUKAI_VERDEX_DIR")
	if verdex == "" {
		verdex = `D:\漏洞挖掘工作台`
	}
	return Config{
		Fairy: mcp.HandConfig{
			Name: Fairy, Cwd: fairy, Cmd: "node",
			Args: []string{"src/cli.js", "mcp"},
		},
		Verdex: mcp.HandConfig{
			Name: Verdex, Cwd: verdex, Cmd: "node",
			Args: []string{"bin/verdex-mcp.mjs"},
		},
	}
}

func requireHands(t *testing.T) Config {
	t.Helper()
	if os.Getenv("YOUKAI_SKIP_INTEGRATION") == "1" {
		t.Skip("integration test disabled by YOUKAI_SKIP_INTEGRATION=1")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH")
	}
	cfg := realHandsConfig()
	if _, err := os.Stat(cfg.Fairy.Cwd); err != nil {
		t.Skipf("Fairy checkout not found at %s", cfg.Fairy.Cwd)
	}
	if _, err := os.Stat(cfg.Verdex.Cwd); err != nil {
		t.Skipf("Verdex checkout not found at %s", cfg.Verdex.Cwd)
	}
	return cfg
}

// TestDialRealHands is the module-1 acceptance test: bring up both real hands and
// confirm they expose the tools the design depends on.
func TestDialRealHands(t *testing.T) {
	cfg := requireHands(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	set, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer set.Close()

	if got := set.Hands(); len(got) != 2 {
		t.Fatalf("connected hands = %v, want both", got)
	}

	// Fairy: the authorisation and planning surface.
	fairyTools := set.ToolNames(Fairy)
	mustHave(t, Fairy, fairyTools, "fairy_scope_init")
	mustHave(t, Fairy, fairyTools, "fairy_planner_tick")
	mustHave(t, Fairy, fairyTools, "fairy_ledger_show")
	mustHave(t, Fairy, fairyTools, "web_probe")
	mustHave(t, Fairy, fairyTools, "web_scan")
	mustHave(t, Fairy, fairyTools, "fairy_ingest")
	mustHave(t, Fairy, fairyTools, "fairy_handoff")

	// Verdex: the static analysis surface.
	verdexTools := set.ToolNames(Verdex)
	mustHave(t, Verdex, verdexTools, "analyze_target")
	mustHave(t, Verdex, verdexTools, "bin_info")
	mustHave(t, Verdex, verdexTools, "bin_decompile")

	info, ok := set.ServerInfo(Fairy)
	if !ok || info.ServerInfo.Name == "" {
		t.Fatalf("Fairy did not report serverInfo: %+v", info)
	}
	if info.ProtocolVersion == "" {
		t.Fatal("Fairy did not report a protocol version")
	}
	info, ok = set.ServerInfo(Verdex)
	if !ok || info.ServerInfo.Name == "" {
		t.Fatalf("Verdex did not report serverInfo: %+v", info)
	}
}

func mustHave(t *testing.T, hand string, tools []string, want string) {
	t.Helper()
	for _, got := range tools {
		if got == want {
			return
		}
	}
	t.Fatalf("%s does not advertise %q (has %d tools)", hand, want, len(tools))
}

// TestHandForRoutesRealTools checks routing against the live inventories,
// including the names that look like they belong to the other hand.
func TestHandForRoutesRealTools(t *testing.T) {
	cfg := requireHands(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	set, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer set.Close()

	cases := map[string]string{
		"web_scan":          Fairy,
		"web_probe":         Fairy,
		"fairy_ledger_show": Fairy,
		"fairy_probe":       Fairy, // documented alias
		"analyze_target":    Verdex,
		"bin_info":          Verdex,
		"web_poc":           Verdex, // "web_" prefix, but Verdex's
		"web_recon":         Verdex,
		"har_analyze":       Verdex,
		"scan":              Verdex,
	}
	for tool, want := range cases {
		got, err := set.HandFor(tool)
		if err != nil {
			t.Fatalf("HandFor(%q): %v", tool, err)
		}
		if got != want {
			t.Fatalf("HandFor(%q) = %q, want %q", tool, got, want)
		}
	}

	if _, err := set.HandFor("definitely_not_a_tool"); err == nil {
		t.Fatal("unknown tool resolved to a hand")
	}
}

// TestOfflineRouting documents the fallback used when a hand is unreachable.
func TestOfflineRouting(t *testing.T) {
	cases := map[string]string{
		"web_probe":         Fairy,
		"fairy_ledger_show": Fairy,
		"har_ingest":        Fairy,
		"analyze_target":    Verdex,
		"web_poc":           Verdex,
		"web_recon":         Verdex,
		"pwn_checksec":      Verdex,
	}
	for tool, want := range cases {
		got, ok := OwnerByPrefix(tool)
		if !ok || got != want {
			t.Fatalf("OwnerByPrefix(%q) = %q,%v want %q", tool, got, ok, want)
		}
	}
	if _, ok := OwnerByPrefix("rm_rf"); ok {
		t.Fatal("unknown tool got a prefix owner")
	}
}

func TestConfigRoundTrip(t *testing.T) {
	path := t.TempDir() + "/.youkai/hands.json"
	cfg := Config{
		Fairy:  mcp.HandConfig{Cwd: "/f", Cmd: "node", Args: []string{"a"}},
		Verdex: mcp.HandConfig{Cwd: "/v", Cmd: "node", Args: []string{"b"}},
	}
	if err := SaveConfig(path, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !strings.EqualFold(got.Fairy.Cwd, cfg.Fairy.Cwd) || !strings.EqualFold(got.Verdex.Cwd, cfg.Verdex.Cwd) {
		t.Fatalf("round trip changed config: %+v", got)
	}
	if f, v := got.Configured(); !f || !v {
		t.Fatal("Configured() rejected a complete config")
	}
}
