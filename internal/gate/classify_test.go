package gate

import "testing"

// TestDocumentedTiers pins the classification table from DEVPLAN-v0.1 section 5.
// If someone moves a tool between tiers, this test makes them do it on purpose.
func TestDocumentedTiers(t *testing.T) {
	cases := []struct {
		action string
		args   map[string]any
		want   Tier
	}{
		// tier 1: read-only evidence gathering
		{"web_probe", map[string]any{"method": "GET"}, TierReadOnly},
		{"web_probe", nil, TierReadOnly},
		{"web_scan", nil, TierReadOnly},
		{"web_browser", nil, TierReadOnly},
		{"web_compare", nil, TierReadOnly},
		{"web_role_matrix", nil, TierReadOnly},
		{"fairy_reachability", nil, TierReadOnly},
		{"fairy_ledger_show", nil, TierReadOnly},
		{"fairy_chain_plan", nil, TierReadOnly},
		{"fairy_planner_tick", nil, TierReadOnly},
		{"har_ingest", nil, TierReadOnly},

		// tier 2: proof-grade / write / active
		{"web_param", nil, TierProof},
		{"web_param_adaptive", nil, TierProof},
		{"web_waf", nil, TierProof},
		{"web_login", nil, TierProof},
		{"fairy_accounts_seed", nil, TierProof},
		{"fairy_accounts_register", nil, TierProof},
		{"web_poc", nil, TierProof},
		{"impact_proof", nil, TierProof},
		{"frida_script", nil, TierProof},

		// tier 1: Verdex static analysis
		{"analyze_target", nil, TierReadOnly},
		{"scan", nil, TierReadOnly},
		{"bin_info", nil, TierReadOnly},
		{"bin_decompile", nil, TierReadOnly},
		{"mobile_unpack", nil, TierReadOnly},
		{"secrets", nil, TierReadOnly},
		{"har_analyze", nil, TierReadOnly},

		// tier 2: Verdex families that produce executable text
		{"pwn_checksec", nil, TierProof},
		{"pwn_gadgets", nil, TierProof},
		{"pwn_libc", nil, TierProof},
		{"pwn_cyclic", nil, TierProof},
		{"pwn_template", nil, TierProof},
		{"pwn_gdbscript", nil, TierProof},
	}
	for _, c := range cases {
		if got := Classify(c.action, c.args); got != c.want {
			t.Errorf("Classify(%q, %v) = %v, want %v", c.action, c.args, got, c.want)
		}
	}
}

func TestUnknownActionFailsClosed(t *testing.T) {
	for _, action := range []string{
		"", "   ", "some_tool_from_the_future", "getshell", "meterpreter_run",
		"exploit_cve_2024_1234",
	} {
		if got := Classify(action, nil); got != TierDeep {
			t.Errorf("Classify(%q) = %v, want tier3 (fail closed)", action, got)
		}
	}
}

func TestArgumentSensitiveClassification(t *testing.T) {
	cases := []struct {
		name   string
		action string
		args   map[string]any
		want   Tier
	}{
		{"GET probe is read-only", "web_probe", map[string]any{"method": "GET"}, TierReadOnly},
		{"POST probe is a write method", "web_probe", map[string]any{"method": "POST"}, TierProof},
		{"lowercase put", "web_probe", map[string]any{"method": "put"}, TierProof},
		{"DELETE", "web_probe", map[string]any{"method": "DELETE"}, TierProof},
		{"replay without allow_write", "web_replay", nil, TierReadOnly},
		{"replay with allow_write", "web_replay", map[string]any{"allow_write": true}, TierProof},
		{"session list", "web_session", map[string]any{"action": "list"}, TierReadOnly},
		{"session create", "web_session", map[string]any{"action": "create"}, TierProof},
		{"handoff register only", "fairy_handoff", map[string]any{"path": "sample.exe"}, TierReadOnly},
		{"handoff url without confirm", "fairy_handoff", map[string]any{"url": "http://x/y.exe"}, TierReadOnly},
		{"handoff url with confirm downloads", "fairy_handoff", map[string]any{"url": "http://x/y.exe", "confirm": true}, TierProof},
		{"worker_run dispatching a probe", "fairy_worker_run", map[string]any{"action": "web_probe"}, TierReadOnly},
		{"worker_run dispatching a param probe", "fairy_worker_run", map[string]any{"action": "web_param"}, TierProof},
		{"worker_run with no action", "fairy_worker_run", nil, TierDeep},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.action, c.args); got != c.want {
				t.Fatalf("Classify(%q, %v) = %v, want %v", c.action, c.args, got, c.want)
			}
		})
	}
}

// TestApproveIsForbiddenEverywhere is the "never auto-approve" rule expressed as
// a classification: youkai cannot even ask a hand to approve.
func TestApproveIsForbiddenEverywhere(t *testing.T) {
	for _, status := range []string{"approve", "APPROVE"} {
		d := Explain("fairy_ledger_advance", map[string]any{"action": status})
		if d.Tier != TierDeep {
			t.Fatalf("ledger approve classified %v, want tier3", d.Tier)
		}
	}
	// Any tier-3 action is refused by the loop's predicate too.
	if AutonomousOK("fairy_ledger_advance", map[string]any{"action": "approve"}) {
		t.Fatal("autonomous loop would allow an approve call")
	}
	// Claim/done bookkeeping is ordinary read-only work.
	if got := Classify("fairy_ledger_advance", map[string]any{"action": "claim"}); got != TierReadOnly {
		t.Fatalf("ledger claim classified %v, want tier1", got)
	}
}

// TestVerifiedUpgradeNeedsHuman pins that candidate->verified is never automatic.
func TestVerifiedUpgradeNeedsHuman(t *testing.T) {
	d := Explain("fairy_ledger_advance", map[string]any{
		"action": "finding-status", "status": "verified",
	})
	if !d.Tier.NeedsHuman() {
		t.Fatalf("verified upgrade classified %v, want tier>=2", d.Tier)
	}
	d = Explain("fairy_ledger_advance", map[string]any{
		"action": "finding-status", "status": "candidate",
	})
	if d.Tier != TierReadOnly {
		t.Fatalf("candidate bookkeeping classified %v, want tier1", d.Tier)
	}
}

// TestOnlyTierOneIsAutonomous is the runtime half of the wall.
func TestOnlyTierOneIsAutonomous(t *testing.T) {
	if !TierReadOnly.AutonomousOK() {
		t.Fatal("tier1 must be executable by the loop")
	}
	if TierProof.AutonomousOK() {
		t.Fatal("tier2 must never be executable by the loop")
	}
	if TierDeep.AutonomousOK() {
		t.Fatal("tier3 must never be executable by the loop")
	}
	// The doc's rule: even a hand-set approved=true does not open tier2 to the
	// loop, because approval is checked by a human path, not a boolean in a file.
	for _, action := range []string{"web_param", "web_waf", "pwn_template", "web_poc"} {
		if AutonomousOK(action, nil) {
			t.Fatalf("%s would be executed unattended", action)
		}
	}
}

// TestExploitProviderIsStubbed is the compile-time half of the wall.
func TestExploitProviderIsStubbed(t *testing.T) {
	p := Provider()
	if p == nil {
		t.Fatal("Provider() returned nil")
	}
	if p.Available() {
		t.Fatalf("OSS build claims an exploit provider is available: %s", p.Reason())
	}
	if p.Reason() == "" {
		t.Fatal("provider must explain itself")
	}
}

func TestDecisionExplainsItself(t *testing.T) {
	d := Explain("web_param", nil)
	if d.Reason == "" {
		t.Fatal("decision has no reason")
	}
	if d.Allowed() {
		t.Fatal("tier2 decision reported as allowed")
	}
	if d.Action != "web_param" {
		t.Fatalf("action = %q", d.Action)
	}
	// Documented alias resolves to the real tool name.
	if got := Explain("fairy_probe", nil).Action; got != "web_probe" {
		t.Fatalf("alias not canonicalised: %q", got)
	}
}
