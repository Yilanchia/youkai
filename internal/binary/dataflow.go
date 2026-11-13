package binary

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"youkai/internal/ledger"
)

type sinkPattern struct {
	Name     string
	Re       *regexp.Regexp
	Severity string
}

type sourcePattern struct {
	Name string
	Re   *regexp.Regexp
}

var dataflowSinks = []sinkPattern{
	{Name: "system", Re: regexp.MustCompile(`\bsystem\s*\(`), Severity: "high"},
	{Name: "popen", Re: regexp.MustCompile(`\bpopen\s*\(`), Severity: "high"},
	{Name: "Runtime.exec", Re: regexp.MustCompile(`Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\b`), Severity: "high"},
	{Name: "eval", Re: regexp.MustCompile(`\beval\s*\(`), Severity: "high"},
	{Name: "exec", Re: regexp.MustCompile(`\bexec(?:ve|vp|vpe|l|lp|le|v|Sync|File)?\s*\(`), Severity: "medium"},
	{Name: "strcpy", Re: regexp.MustCompile(`\bstrcpy\s*\(`), Severity: "medium"},
	{Name: "strcat", Re: regexp.MustCompile(`\bstrcat\s*\(`), Severity: "medium"},
	{Name: "sprintf", Re: regexp.MustCompile(`\bsprintf\s*\(`), Severity: "medium"},
}

var dataflowSources = []sourcePattern{
	{Name: "argv", Re: regexp.MustCompile(`\bargv\b`)},
	{Name: "request.getParameter", Re: regexp.MustCompile(`getParameter\s*\(`)},
	{Name: "req.query", Re: regexp.MustCompile(`\breq\s*\.\s*query\b`)},
	{Name: "req.body", Re: regexp.MustCompile(`\breq\s*\.\s*body\b`)},
	{Name: "process.argv", Re: regexp.MustCompile(`process\s*\.\s*argv\b`)},
	{Name: "fgets", Re: regexp.MustCompile(`\bfgets\s*\(`)},
	{Name: "read", Re: regexp.MustCompile(`\bread\s*\(`)},
	{Name: "scanf", Re: regexp.MustCompile(`\bscanf\s*\(|\bgets\s*\(`)},
	{Name: "getenv", Re: regexp.MustCompile(`\bgetenv\s*\(`)},
}

var cFuncHeaderRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{?\s*$`)

var defaultDataflowExts = map[string]bool{
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true, ".hpp": true,
	".java": true, ".kt": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true,
	".jsx": true, ".tsx": true,
}

// dataflowCapability is a heuristic source-to-sink sweep over source trees. It
// is not a dataflow solver: it says "a user-controlled name appears in the same
// function as a dangerous sink", and labels itself as such.
func dataflowCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	root, info, err := inputPathAllowDir(argString(args, "path"))
	if err != nil {
		return ledger.Observation{}, err
	}
	exts := parseExtFilter(argString(args, "ext"))

	files := []string{}
	if info.IsDir() {
		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.IsDir() {
				if skipScanDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if len(files) >= 3000 {
				return filepath.SkipAll
			}
			if !exts[strings.ToLower(filepath.Ext(p))] {
				return nil
			}
			if info, err := d.Info(); err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
				return nil
			}
			files = append(files, p)
			return nil
		})
		if walkErr != nil {
			return ledger.Observation{}, walkErr
		}
	} else {
		files = append(files, root)
	}

	obs := ledger.Observation{}
	sinkTotal := 0
	findings := 0
	var totalBytes int64
	for _, file := range files {
		if findings >= 100 || totalBytes > maxDirBytes {
			break
		}
		if err := ctx.Err(); err != nil {
			return ledger.Observation{}, err
		}
		data, readErr := os.ReadFile(file)
		if readErr != nil {
			continue
		}
		totalBytes += int64(len(data))
		if len(data) > 4<<20 {
			data = data[:4<<20]
		}
		lines := strings.Split(string(data), "\n")
		seen := map[string]bool{}
		for i, line := range lines {
			if findings >= 100 {
				break
			}
			if isCommentLine(line) {
				continue
			}
			var sink sinkPattern
			foundSink := false
			for _, s := range dataflowSinks {
				if s.Re.MatchString(line) {
					sink, foundSink = s, true
					break
				}
			}
			if !foundSink {
				continue
			}
			sinkTotal++
			start, end, function := functionSpan(lines, i)
			sourceName, sourceLine := "", -1
			for j := start; j <= end && j < len(lines); j++ {
				if isCommentLine(lines[j]) {
					continue
				}
				for _, src := range dataflowSources {
					if !src.Re.MatchString(lines[j]) {
						continue
					}
					switch {
					case sourceLine < 0:
						sourceName, sourceLine = src.Name, j
					case sourceLine > i && j <= i:
						// Prefer a source before the sink over one after it.
						sourceName, sourceLine = src.Name, j
					case j <= i && j > sourceLine:
						// Keep the closest preceding source.
						sourceName, sourceLine = src.Name, j
					case sourceLine > i && j > i && j < sourceLine:
						// Otherwise the closest following source.
						sourceName, sourceLine = src.Name, j
					}
				}
			}
			if sourceLine < 0 {
				continue
			}
			key := fmt.Sprintf("%d|%s", i, sink.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
			findings++
			where := fmt.Sprintf("%s:%d", file, i+1)
			taintPath := fmt.Sprintf("%s:%d %s → %s:%d %s",
				filepath.Base(file), sourceLine+1, sourceName,
				filepath.Base(file), i+1, sink.Name)
			obs.Findings = append(obs.Findings, newFinding(
				fmt.Sprintf("疑似可控输入流向危险函数 %s", sink.Name),
				sink.Severity, "dataflow", where,
				fmt.Sprintf("启发式同函数可达性(非数据流求解器):%s。仅静态推断,未执行任何代码;参数实际可控性需人工确认。", taintPath),
				evidenceWithLocation(file, map[string]any{
					"path":        file,
					"line":        i + 1,
					"sink":        sink.Name,
					"source":      sourceName,
					"source_line": sourceLine + 1,
					"function":    function,
					"heuristic":   true,
					"executed":    false,
					"source_kind": "heuristic-same-function",
				}),
				[]string{"binary", "dataflow", "tier1"},
				[]string{"artifact:" + root},
			))
		}
	}

	statement := fmt.Sprintf(
		"dataflow: %s 扫描源码 %d 个文件,危险 sink=%d 处,同函数可达候选=%d(启发式,未执行)",
		root, len(files), sinkTotal, findings)
	obs.Facts = append(obs.Facts, newFact(statement,
		evidenceWithLocation(root, map[string]any{
			"path":        root,
			"files":       len(files),
			"sink_total":  sinkTotal,
			"candidates":  findings,
			"bytes":       totalBytes,
			"heuristic":   true,
			"limitation":  "只做同函数/文件内的符号名可达性,不跟踪赋值、净化函数或跨函数调用",
			"executed":    false,
			"source_kind": "native-heuristic",
		}),
		[]string{"binary", "dataflow", "tier1"}, []string{"artifact:" + root}))
	obs.Summary = statement
	return obs, nil
}

func parseExtFilter(raw string) map[string]bool {
	if strings.TrimSpace(raw) == "" {
		return defaultDataflowExts
	}
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		ext := strings.ToLower(strings.TrimSpace(part))
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		out[ext] = true
	}
	if len(out) == 0 {
		return defaultDataflowExts
	}
	return out
}

func isCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "#")
}

// functionSpan guesses the enclosing function of line. It is deliberately
// simple: the result is labelled heuristic everywhere it is used.
func functionSpan(lines []string, line int) (start, end int, name string) {
	start = line
	name = ""
	for i := line; i >= 0 && i > line-150; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, ";") {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "if ") || strings.HasPrefix(lower, "if(") ||
			strings.HasPrefix(lower, "for") || strings.HasPrefix(lower, "while") ||
			strings.HasPrefix(lower, "switch") || strings.HasPrefix(lower, "catch") ||
			strings.HasPrefix(lower, "else") {
			continue
		}
		if strings.Contains(trimmed, "(") && (strings.HasSuffix(trimmed, "{") || strings.HasSuffix(trimmed, ")")) {
			if m := cFuncHeaderRe.FindStringSubmatch(trimmed); m != nil {
				start = i
				name = m[1]
				break
			}
		}
	}
	if start == line {
		// No obvious header: fall back to a bounded window.
		start = line - 30
		if start < 0 {
			start = 0
		}
		end = line + 30
		if end >= len(lines) {
			end = len(lines) - 1
		}
		return start, end, ""
	}

	// Walk forward to the matching closing brace, bounded.
	depth := 0
	opened := false
	end = start
	for i := start; i < len(lines) && i < start+400; i++ {
		open := strings.Count(lines[i], "{")
		closing := strings.Count(lines[i], "}")
		depth += open - closing
		if open > 0 {
			opened = true
		}
		if opened && depth <= 0 {
			end = i
			return start, end, name
		}
		end = i
	}
	return start, end, name
}
