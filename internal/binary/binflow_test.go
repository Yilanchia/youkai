package binary

import (
	"os"
	"strings"
	"testing"

	"youkai/internal/ledger"
)

// TestBinflowPairsArgvWithSystem: the pure pairing is what the capability rests on.
func TestBinflowPairsArgvWithSystem(t *testing.T) {
	disasm := `
0000000000001149 <main>:
  1149: mov rax, [rbp-0x8]      ; argv
  1152: call system@plt
  1157: call strcpy@plt
`
	hyps := deriveBinHypotheses(disasm, nil, false)
	if len(hyps) == 0 {
		t.Fatal("no hypotheses from argv → system/strcpy")
	}
	var rce, mem bool
	for _, h := range hyps {
		if h.Sink == "system" && h.Kind == "rce" {
			rce = true
		}
		if h.Sink == "strcpy" && h.Kind == "memory" {
			mem = true
		}
		if h.Kind == "" || h.Path == "" {
			t.Fatalf("hypothesis is missing its evidence: %+v", h)
		}
	}
	if !rce {
		t.Fatalf("command-execution lead missing: %+v", hyps)
	}
	if !mem {
		t.Fatalf("memory lead missing: %+v", hyps)
	}
}

// TestBinflowNeedsAnInput: sinks alone are not a lead.
func TestBinflowNeedsAnInput(t *testing.T) {
	if hyps := deriveBinHypotheses("call system@plt", nil, false); len(hyps) != 0 {
		t.Fatalf("a sink without a source produced leads: %+v", hyps)
	}
}

// TestBinflowMarksBlindedSamples: the label travels with the hypothesis.
func TestBinflowMarksBlindedSamples(t *testing.T) {
	hyps := deriveBinHypotheses("argv ... call system@plt", nil, true)
	if len(hyps) == 0 {
		t.Fatal("no lead")
	}
	if !hyps[0].Blinded {
		t.Fatal("the hypothesis does not carry the blinded label")
	}
}

// TestBinflowIsCodeOnly: the observation must never claim a finding.
func TestBinflowIsCodeOnly(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sample.bin"
	body := "argv system strcpy sprintf"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	env := &Env{ArtifactDir: dir, EngagementID: 1, Engagement: "lab"}
	obs, err := Run(nil, env, "binflow", map[string]any{"path": path})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(obs.Findings) != 0 {
		t.Fatalf("binflow produced findings, it must only produce leads: %+v", obs.Findings)
	}
	var tagged bool
	for _, f := range obs.Facts {
		if strings.Contains(f.Statement, "confidence=code-only") || strings.Contains(f.Statement, "线索") {
			tagged = true
			if !hasTag(f.Tags, "code-only") {
				t.Fatalf("a lead is missing its code-only tag: %+v", f)
			}
		}
	}
	if !tagged {
		t.Fatalf("no hypothesis facts: %+v", obs.Facts)
	}
}

// TestBlindedSecretsAreDowngraded: a poisoned sample turns surface hits into notes.
func TestBlindedSecretsAreDowngraded(t *testing.T) {
	surface := []ledger.FindingSeed{
		{Title: "硬编码凭据:AWS", Severity: "high", Kind: "secret", Where: "x:1", Counter: "c"},
		{Title: "硬编码凭据:low", Severity: "low", Kind: "secret", Where: "x:2"},
	}
	blind := blindContext{Level: BlindSuspected, Signals: 2, Note: "样本疑似经过对抗处理:这条属于表面证据,可信度降低,需结构证据"}
	kept, notes := blind.applyToFindings(surface)
	if len(notes) != 2 {
		t.Fatalf("notes = %d, want one per surface hit", len(notes))
	}
	if len(kept) != 1 {
		t.Fatalf("kept = %d, want only the high-severity hit (downgraded)", len(kept))
	}
	if kept[0].Severity != "medium" {
		t.Fatalf("severity = %q, want medium after downgrade", kept[0].Severity)
	}
	if !strings.Contains(kept[0].Counter, "可信度降低") {
		t.Fatalf("the downgraded finding does not say why: %q", kept[0].Counter)
	}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
