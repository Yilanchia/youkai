package binary

import (
	"context"
	"fmt"
	"os"

	"youkai/internal/ledger"
)

// blindScreen is the sample-level anti-analysis check.
//
// It reads the file and the strings already recoverable from it, labels how much
// the sample looks like it was built to mislead an analyser, and stops there. It
// never unpacks, never executes, and never claims a vulnerability: the output is a
// confidence label plus the structural signals that produced it.
func blindScreen(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, size, err := inputFilePath(argString(args, "path"), false)
	if err != nil {
		return ledger.Observation{}, err
	}
	if err := ctx.Err(); err != nil {
		return ledger.Observation{}, err
	}
	// Bounded read: the label needs shape, not the whole sample.
	const maxRead = 4 << 20
	data := make([]byte, 0, min64(size, maxRead))
	f, err := os.Open(path)
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("%w: open %s: %v", ErrRefused, path, err)
	}
	defer f.Close()
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

	// Reuse the strings pass so both capabilities describe the same sample.
	ascii, utf16 := extractStrings(data, 4, 1<<20, ctx)
	var strs []string
	for _, r := range ascii {
		strs = append(strs, r.Value)
	}
	for _, r := range utf16 {
		strs = append(strs, r.Value)
	}
	rep := analyseBlindness(data, strs, nil)

	obs := ledger.Observation{}
	facts, findings := blindObservation(rep)
	obs.Facts = append(obs.Facts, ledger.FactSeed{
		Statement: "反致盲结论:可信度 = " + string(rep.Level) + "(" + fmt.Sprint(len(rep.Signals)) + " 类信号;" +
			fmt.Sprint(len(data)) + " 字节被抽样)",
		Evidence: map[string]any{"level": string(rep.Level), "signals": len(rep.Signals), "bytes": len(data)},
	})
	obs.Facts = append(obs.Facts, facts...)
	for _, n := range rep.Notes {
		obs.Facts = append(obs.Facts, ledger.FactSeed{Statement: "反致盲提示:" + n})
	}
	obs.Findings = append(obs.Findings, findings...)
	obs.Summary = "blind_screen " + string(rep.Level)
	return obs, nil
}

func min64(a int64, b int) int {
	if a < int64(b) {
		return int(a)
	}
	return b
}
