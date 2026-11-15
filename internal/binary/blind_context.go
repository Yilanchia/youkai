package binary

import (
	"context"
	"os"

	"youkai/internal/ledger"
)

// Blinding applies the sample's anti-analysis label to the rest of the analysis.
//
// The rule is blunt on purpose: on a sample that looks built to mislead, an
// observation that rests on its SYMBOLS or STRINGS is not evidence. It is still
// recorded - the operator may want to see it - but as a note tagged "surface, low
// trust", never as a finding. Structural observations are unaffected.
//
// This is the second half of v0.16: blind_screen produced the label, and this is
// where the label starts changing what youkai is willing to claim.

// blindContext is the label plus a short explanation for a path.
type blindContext struct {
	Level   BlindLevel
	Signals int
	Note    string
}

// blindForPath runs the same structural measurement blind_screen uses, on a bounded
// prefix of the file. It never executes anything.
func blindForPath(path string) blindContext {
	f, err := os.Open(path)
	if err != nil {
		return blindContext{Level: BlindClean}
	}
	defer f.Close()
	const maxRead = 2 << 20
	data := make([]byte, 0, 64<<10)
	buf := make([]byte, 64<<10)
	for len(data) < maxRead {
		n, rerr := f.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	ascii, utf16 := extractStrings(data, 4, 1<<20, context.Background())
	var strs []string
	for _, r := range ascii {
		strs = append(strs, r.Value)
	}
	for _, r := range utf16 {
		strs = append(strs, r.Value)
	}
	rep := analyseBlindness(data, strs, nil)
	ctx := blindContext{Level: rep.Level, Signals: len(rep.Signals)}
	if rep.Level != BlindClean {
		ctx.Note = "样本疑似经过对抗处理(" + string(rep.Level) + "):这条属于**表面证据**,可信度降低,需结构证据或人工复核"
	}
	return ctx
}

// blinded reports whether surface evidence should be downgraded.
func (b blindContext) blinded() bool { return b.Level != BlindClean }

// applyToFindings moves surface observations out of the findings list when the
// sample is blinded, and returns the notes that replaced them.
//
// "Not a finding" is not the same as "not worth recording": the note keeps the
// location, the rule id and the redacted preview, so a human can still look.
func (b blindContext) applyToFindings(findings []ledger.FindingSeed) (kept []ledger.FindingSeed, notes []ledger.FactSeed) {
	if !b.blinded() {
		return findings, nil
	}
	for _, f := range findings {
		notes = append(notes, ledger.FactSeed{
			Statement: "表面证据(未计为发现):" + f.Title + " @ " + f.Where + " — " + b.Note,
			Evidence: map[string]any{
				"surface": true, "kind": f.Kind, "severity_if_trusted": f.Severity,
				"blind_level": string(b.Level), "where": f.Where,
			},
			Tags: []string{"blinded", "surface-only"},
		})
		// Keep a downgraded copy as a finding only when it is at least medium: a
		// leaked key is worth a human's attention even in a poisoned sample, and the
		// counter says exactly how much to trust it.
		if f.Severity == "critical" || f.Severity == "high" || f.Severity == "medium" {
			downgraded := f
			downgraded.Severity = downgradeSeverity(f.Severity)
			downgraded.Counter = joinCounter(f.Counter, b.Note)
			kept = append(kept, downgraded)
		}
	}
	return kept, notes
}

func downgradeSeverity(s string) string {
	switch s {
	case "critical":
		return "medium"
	case "high":
		return "medium"
	case "medium":
		return "low"
	default:
		return "info"
	}
}

func joinCounter(existing, note string) string {
	if existing == "" {
		return note
	}
	return note + "。" + existing
}
