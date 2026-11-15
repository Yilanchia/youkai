package binary

import (
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// binflow: the binary-side twin of the web whitebox dataflow.
//
// It looks for the same shape a human looks for when reading a disassembly: an
// input the program does not control (argv, recv, read, getenv) flowing into a call
// that does something dangerous with it (system, exec, strcpy, sprintf, printf).
//
// Everything it produces is a HYPOTHESIS with confidence code-only. It is a lead,
// never a finding: exploitability needs a human, a debugger and an authorisation.
// It is also pure text matching over strings and disassembly text - no execution,
// no emulation, no symbolic solving.

type binHypothesis struct {
	Source   string // argv / recv / read / fgets / getenv
	Sink     string // system / execve / strcpy / sprintf / memcpy / printf
	Kind     string // rce / memory / format
	Detail   string
	Path     string // "symbolA → symbolB" or file:line when the backend has source
	Blinded  bool
	Severity string
}

// Input and sink vocabulary, matched against disassembly symbol references.
var (
	binSources = []string{"argv", "__libc_start_main", "recv", "recvfrom", "read", "fgets", "gets", "getenv", "scanf", "fread"}
	binSinks   = []struct {
		Name string
		Kind string
		Why  string
	}{
		{"system", "rce", "命令执行"},
		{"popen", "rce", "命令执行"},
		{"execve", "rce", "命令执行"},
		{"execl", "rce", "命令执行"},
		{"execvp", "rce", "命令执行"},
		{"strcpy", "memory", "无界拷贝"},
		{"strcat", "memory", "无界拼接"},
		{"sprintf", "memory", "无界格式化输出"},
		{"memcpy", "memory", "长度可控拷贝"},
		{"printf", "format", "格式化串"},
		{"syslog", "format", "格式化串"},
	}
	reSymbolRef = regexp.MustCompile(`(?i)\b(system|popen|execve|execl|execvp|strcpy|strcat|sprintf|memcpy|printf|syslog|recv|recvfrom|fgets|gets|getenv|scanf|fread)\b`)
)

// binflowCapability reads a disassembly listing (from the existing disasm backend)
// or the sample's strings and emits hypotheses.
//
// args: path (required), symbols (optional pre-extracted list), blinded (optional
// label from blind_screen; when absent it is measured here).
func binflowCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, _, err := inputFilePath(argString(args, "path"), false)
	if err != nil {
		return ledger.Observation{}, err
	}
	if err := ctx.Err(); err != nil {
		return ledger.Observation{}, err
	}
	blind := blindForPath(path)

	// The disassembly text is the structural side; strings are the surface side.
	// Both are used, and a blinded sample is marked apart in the output.
	disasm := disassemblyText(ctx, path)
	strs := stringsOf(path)

	hyps := deriveBinHypotheses(disasm, strs, blind.Level != BlindClean)
	obs := ledger.Observation{}
	obs.Facts = append(obs.Facts, ledger.FactSeed{
		Statement: "二进制数据流假设:" + path + " 产出 " + foo(len(hyps)) + " 条线索(confidence=code-only,未执行)",
		Evidence: map[string]any{
			"path": path, "hypotheses": len(hyps),
			"blind_level": string(blind.Level), "disasm_available": disasm != "",
		},
		Tags: []string{"binflow", "code-only"},
	})
	for _, h := range hyps {
		obs.Facts = append(obs.Facts, ledger.FactSeed{
			Statement: "线索(" + h.Kind + "):" + h.Source + " → " + h.Sink + "(" + h.Detail + ") " + h.Path,
			Evidence: map[string]any{
				"source": h.Source, "sink": h.Sink, "kind": h.Kind, "path": h.Path,
				"confidence": "code-only", "blinded": h.Blinded,
			},
			Tags: []string{"binflow", "code-only", "hypothesis"},
		})
	}
	if len(hyps) > 0 {
		obs.Summary = "binflow: " + foo(len(hyps)) + " 条线索(code-only)"
	}
	return obs, nil
}

// deriveBinHypotheses is the pure part: given a disassembly text and strings,
// pair an input symbol with a dangerous sink when both appear.
func deriveBinHypotheses(disasm string, strs []string, blinded bool) []binHypothesis {
	text := strings.ToLower(disasm)
	for _, s := range strs {
		text += "\n" + strings.ToLower(s)
	}
	// Sinks come from symbol references; sources are plain substrings (argv rarely
	// appears as a symbol of its own in a stripped binary).
	present := map[string]bool{}
	for _, m := range reSymbolRef.FindAllStringSubmatch(text, -1) {
		present[strings.ToLower(m[1])] = true
	}
	var sources []string
	for _, s := range binSources {
		if strings.Contains(text, strings.ToLower(s)) {
			sources = append(sources, s)
		}
	}
	if len(sources) == 0 {
		return nil
	}
	var out []binHypothesis
	for _, sink := range binSinks {
		if !present[sink.Name] {
			continue
		}
		// sprintf/printf take a format string; a source reaching them is the
		// classic format-string lead. strcpy/memcpy from a read source is memory.
		for _, src := range sources {
			if lopsided(src, sink.Name) {
				continue
			}
			sev := "high"
			if sink.Kind == "format" {
				sev = "medium"
			}
			out = append(out, binHypothesis{
				Source: src, Sink: sink.Name, Kind: sink.Kind, Severity: sev,
				Detail: "输入点 " + src + " 与 " + sink.Why + " 调用 " + sink.Name + " 同时出现;" +
					"这是符号级可达性,不是数据流证明",
				Path:    src + " → " + sink.Name,
				Blinded: blinded,
			})
			break // one source per sink keeps the list readable
		}
		if len(out) >= 12 {
			break
		}
	}
	return out
}

// lopsided drops pairings that never make sense (recv → printf is a format-string
// lead, but getenv → printf is far weaker than argv → printf).
func lopsided(source, sink string) bool {
	if sink == "printf" || sink == "syslog" {
		return source != "argv" && source != "recv" && source != "gets" && source != "fgets" && source != "scanf"
	}
	return false
}

func foo(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

var _ = gate.TierReadOnly

// disassemblyText runs objdump when it is available and returns the listing text.
// A missing backend is not an error here: the hypotheses then rest on strings only,
// and the fact says so.
func disassemblyText(ctx context.Context, path string) string {
	toolPath, found := findTool("objdump", "")
	if !found {
		return ""
	}
	if _, runnable := runnableExecutable(toolPath); !runnable {
		return ""
	}
	out, _, err := runTool(ctx, 60*time.Second, toolPath,
		[]string{"-d", "--no-show-raw-insn", "-M", "intel", path}, 8<<20)
	if err != nil && strings.TrimSpace(out) == "" {
		return ""
	}
	return out
}

// stringsOf returns the printable strings of a file, bounded, for the surface side.
func stringsOf(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	const maxRead = 8 << 20
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
	var out []string
	for _, r := range ascii {
		out = append(out, r.Value)
	}
	for _, r := range utf16 {
		out = append(out, r.Value)
	}
	return out
}
