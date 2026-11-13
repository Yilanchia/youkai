package gate

import "testing"

// TestDocumentedTiers pins DEVPLAN-v0.2's classification intent.
func TestDocumentedTiers(t *testing.T) {
	cases := []struct {
		capability string
		args       map[string]any
		want       Tier
	}{
		// web tier 1
		{"probe", map[string]any{"method": "GET"}, TierReadOnly},
		{"probe", nil, TierReadOnly},
		{"scan", nil, TierReadOnly},
		{"crawl", nil, TierReadOnly},
		{"compare", nil, TierReadOnly},
		{"role_matrix", nil, TierReadOnly},
		{"reachability", nil, TierReadOnly},
		{"proof", nil, TierReadOnly},
		{"fingerprint", nil, TierReadOnly},
		{"browser", nil, TierReadOnly},

		// web tier 2
		{"param", nil, TierProof},
		{"param_adaptive", nil, TierProof},
		{"waf", nil, TierProof},
		{"login", nil, TierProof},
		{"accounts_seed", nil, TierProof},
		{"accounts_register", nil, TierProof},

		// binary tier 1
		{"artifact_identify", nil, TierReadOnly},
		{"artifact_register", nil, TierReadOnly},
		{"strings", nil, TierReadOnly},
		{"checksec", nil, TierReadOnly},
		{"decompile", nil, TierReadOnly},
		{"mobile_unpack", nil, TierReadOnly},
		{"secrets", nil, TierReadOnly},
		{"dataflow", nil, TierReadOnly},
		{"sarif", nil, TierReadOnly},
		{"doctor", nil, TierReadOnly},

		// binary tier 2
		{"pwn_template", nil, TierProof},
		{"pwn_checksec", nil, TierProof},
		{"impact_proof", nil, TierProof},
		{"frida_script", nil, TierProof},
		{"download", nil, TierProof},
	}
	for _, c := range cases {
		if got := Classify(c.capability, c.args); got != c.want {
			t.Errorf("Classify(%q) = %v, want %v", c.capability, got, c.want)
		}
	}
}

func TestUnknownCapabilityFailsClosed(t *testing.T) {
	for _, c := range []string{"", "   ", "getshell", "meterpreter_run", "lateral_move", "exfil_data", "future_capability"} {
		if got := Classify(c, nil); got != TierDeep {
			t.Errorf("Classify(%q) = %v, want tier3", c, got)
		}
	}
}

func TestWriteMethodEscalates(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "post"} {
		if got := Classify("probe", map[string]any{"method": m}); got != TierProof {
			t.Fatalf("probe method %s classified %v, want tier2", m, got)
		}
	}
	if got := Classify("probe", map[string]any{"method": "HEAD"}); got != TierReadOnly {
		t.Fatalf("HEAD classified %v", got)
	}
}

func TestOnlyTierOneIsAutonomous(t *testing.T) {
	if !TierReadOnly.AutonomousOK() {
		t.Fatal("tier1 must be autonomous")
	}
	for _, tier := range []Tier{TierProof, TierDeep} {
		if tier.AutonomousOK() {
			t.Fatalf("%v must never be autonomous", tier)
		}
	}
	for _, c := range []string{"param", "waf", "pwn_template", "impact_proof"} {
		if AutonomousOK(c, nil) {
			t.Fatalf("%s would run unattended", c)
		}
	}
}

func TestExploitProviderIsStubbed(t *testing.T) {
	p := Provider()
	if p == nil {
		t.Fatal("Provider() returned nil")
	}
	if p.Available() {
		t.Fatalf("OSS build claims an exploit provider: %s", p.Reason())
	}
	if p.Reason() == "" {
		t.Fatal("provider must explain itself")
	}
}

func TestCapabilityLists(t *testing.T) {
	ro := ReadOnlyCapabilities()
	if len(ro) < 15 {
		t.Fatalf("read-only list looks wrong: %v", ro)
	}
	for _, c := range ro {
		if !AutonomousOK(c, nil) {
			t.Fatalf("%s is listed read-only but is not autonomous", c)
		}
	}
	proof := ProofCapabilities()
	for _, c := range proof {
		if AutonomousOK(c, nil) {
			t.Fatalf("%s is listed proof-grade but is autonomous", c)
		}
	}
	// The lists must not overlap.
	index := map[string]bool{}
	for _, c := range ro {
		index[c] = true
	}
	for _, c := range proof {
		if index[c] {
			t.Fatalf("%s is in both lists", c)
		}
	}
}

func TestDecisionExplainsItself(t *testing.T) {
	d := Explain("param", nil)
	if d.Reason == "" || d.Allowed() {
		t.Fatalf("bad decision: %+v", d)
	}
	if d.Capability != "param" {
		t.Fatal("capability not echoed")
	}
}
