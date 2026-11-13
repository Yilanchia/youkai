package binary

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"youkai/internal/ledger"
)

// dangerousImport is one C library / runtime symbol worth flagging. It is a
// review lead, not a vulnerability: the finding says so.
type dangerousImport struct {
	Name       string
	Severity   string
	Note       string
	ExecPrefix bool
}

var dangerousImports = []dangerousImport{
	{Name: "strcpy", Severity: "low", Note: "无边界字符串拷贝"},
	{Name: "strcat", Severity: "low", Note: "无边界字符串拼接"},
	{Name: "sprintf", Severity: "low", Note: "无边界格式化输出"},
	{Name: "vsprintf", Severity: "low", Note: "无边界格式化输出"},
	{Name: "gets", Severity: "medium", Note: "无边界输入(已从现代 libc 移除)"},
	{Name: "system", Severity: "medium", Note: "命令执行"},
	{Name: "popen", Severity: "medium", Note: "命令执行"},
	{Name: "memcpy", Severity: "info", Note: "长度可控时可能溢出"},
	{Name: "exec", Severity: "medium", Note: "进程替换/执行", ExecPrefix: true},
}

// dangerousImportRes is compiled once. Matching is case-sensitive and the
// "exec" family needs an explicit suffix, so Go/Java package paths such as
// "os/exec.Command", "fmt.Sprintf", and the Go syscall wrapper do not
// false-positive.
var dangerousImportRes = func() map[string]*regexp.Regexp {
	out := make(map[string]*regexp.Regexp, len(dangerousImports))
	for _, d := range dangerousImports {
		if d.ExecPrefix {
			out[d.Name] = regexp.MustCompile(`\bexec(?:ve|vpe|vp|v|lp|le|l)\b`)
			continue
		}
		out[d.Name] = regexp.MustCompile(`\b` + regexp.QuoteMeta(d.Name) + `\b`)
	}
	return out
}()

// matchDangerousName resolves a symbol/import name to a rule. It tolerates
// @GLIBC version suffixes, leading underscores, and +0x offsets, but stays
// case-sensitive so language-level names are not mistaken for C imports.
func matchDangerousName(name string) (dangerousImport, bool) {
	normalized := strings.TrimSpace(name)
	if idx := strings.IndexByte(normalized, '@'); idx >= 0 {
		normalized = normalized[:idx]
	}
	if idx := strings.IndexByte(normalized, '+'); idx >= 0 {
		normalized = normalized[:idx]
	}
	normalized = strings.TrimLeft(normalized, "_")
	for _, d := range dangerousImports {
		if d.ExecPrefix {
			if dangerousImportRes[d.Name].MatchString(normalized) {
				return d, true
			}
			continue
		}
		if normalized == d.Name {
			return d, true
		}
	}
	return dangerousImport{}, false
}

// symbolsCapability lists symbols/imports through nm, readelf, or objdump when
// one exists. With no backend it emits an explicit "not executed" fact.
func symbolsCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, size, err := inputFilePath(argString(args, "path"), true)
	if err != nil {
		return ledger.Observation{}, err
	}

	backendName, backendPath, backendArgs, ok := pickSymbolBackend(path)
	if !ok {
		statement := fmt.Sprintf("symbols: %s 未执行: 未找到 nm/readelf/objdump 后端,无法列出符号(未伪造结果)", path)
		evidence := evidenceWithLocation(path, map[string]any{
			"path":     path,
			"size":     size,
			"backend":  "none",
			"executed": false,
			"source":   "backend-probe",
			"degraded": "install binutils (nm/readelf/objdump) to enable symbol analysis",
		})
		return ledger.Observation{
			Facts: []ledger.FactSeed{newFact(statement, evidence,
				[]string{"binary", "symbols", "degraded", "tier1"}, []string{"artifact:" + path})},
			Summary: statement,
		}, nil
	}

	out, truncated, runErr := runTool(ctx, defaultToolTimeout, backendPath, backendArgs, maxToolOutput)
	lineCount := 0
	examples := map[string]string{}
	counts := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lineCount++
		for _, d := range dangerousImports {
			if danger := dangerInLine(line, d); danger {
				counts[d.Name]++
				if _, seen := examples[d.Name]; !seen {
					examples[d.Name] = clipString(strings.TrimSpace(line), 200)
				}
			}
		}
	}

	obs := ledger.Observation{}
	for _, d := range dangerousImports {
		n := counts[d.Name]
		if n == 0 {
			continue
		}
		obs.Findings = append(obs.Findings, newFinding(
			fmt.Sprintf("危险导入或符号: %s(%s)", d.Name, d.Note),
			d.Severity, "dangerous-import", path,
			fmt.Sprintf("后端 %s 的输出中出现 %d 处 %s(%s)。这是待复核的候选:实际可利用性取决于调用点与参数来源。", backendName, n, d.Name, d.Note),
			evidenceWithLocation(path, map[string]any{
				"path":    path,
				"symbol":  d.Name,
				"count":   n,
				"backend": backendName,
				"example": examples[d.Name],
				"source":  "external-backend:" + backendName,
			}),
			[]string{"binary", "symbols", "imports", "tier1"},
			[]string{"artifact:" + path},
		))
	}

	if runErr != nil {
		statement := fmt.Sprintf("symbols: %s 后端 %s 执行失败,未产出符号(%s);未伪造结果",
			path, backendName, clipString(runErr.Error(), 160))
		evidence := evidenceWithLocation(path, map[string]any{
			"path": path, "backend": backendName, "error": clipString(runErr.Error(), 300),
			"source": "external-backend:" + backendName, "executed": false,
		})
		obs.Facts = append(obs.Facts, newFact(statement, evidence,
			[]string{"binary", "symbols", "degraded", "tier1"}, []string{"artifact:" + path}))
		obs.Summary = statement
		return obs, nil
	}

	statement := fmt.Sprintf("symbols: %s backend=%s 符号/导入行=%d 危险导入=%d",
		path, backendName, lineCount, countMapTotal(counts))
	evidence := evidenceWithLocation(path, map[string]any{
		"path":       path,
		"backend":    backendName,
		"line_count": lineCount,
		"dangerous":  counts,
		"truncated":  truncated,
		"source":     "external-backend:" + backendName,
		"size":       size,
		"limitation": "危险导入按符号名启发式匹配;C++ mangled 名称与 stripped 二进制可能漏报",
	})
	obs.Facts = append(obs.Facts, newFact(statement, evidence,
		[]string{"binary", "symbols", "tier1"}, []string{"artifact:" + path}))
	obs.Summary = statement
	return obs, nil
}

// pickSymbolBackend prefers nm (smallest output), then readelf, then objdump.
// The argv is fixed here; no caller string ever reaches it.
func pickSymbolBackend(path string) (name, tool string, args []string, ok bool) {
	if p, found := findTool("nm", ""); found {
		return "nm", p, []string{path}, true
	}
	if p, found := findTool("readelf", ""); found {
		return "readelf", p, []string{"-sW", path}, true
	}
	if p, found := findTool("objdump", ""); found {
		return "objdump", p, []string{"-t", path}, true
	}
	return "", "", nil, false
}

// dangerInLine checks the symbol token (last whitespace-separated field of an
// nm/readelf/objdump line) and rejects language-qualified names such as
// "flag.(*FlagSet).sprintf" or "os/exec.Command".
func dangerInLine(line string, d dangerousImport) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	name := fields[len(fields)-1]
	base := name
	if idx := strings.IndexByte(base, '@'); idx >= 0 {
		base = base[:idx]
	}
	if strings.ContainsAny(base, "./\\") {
		return false
	}
	matched, ok := matchDangerousName(name)
	return ok && matched.Name == d.Name
}

func countMapTotal(m map[string]int) int {
	total := 0
	for _, v := range m {
		total += v
	}
	return total
}
