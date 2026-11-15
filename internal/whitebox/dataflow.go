package whitebox

import (
	"regexp"
	"sort"
	"strings"
)

// Flow analysis: source -> sink, heuristically.
//
// This is deliberately a "grep with taste" rather than a real dataflow engine. It
// tracks identifiers assigned from a request source and looks for those identifiers
// inside a dangerous call, in the same file. That produces false positives (a
// variable reused for something else) and false negatives (taint through a helper
// function) - which is exactly why every result is labelled code-only and must be
// confirmed by an actual request.

type sinkClass struct {
	name string
	re   *regexp.Regexp
	// why is the sentence that goes on the hypothesis.
	why string
}

var sinks = []sinkClass{
	{"sql-concat", regexp.MustCompile(`(?i)\b(query|execute|executemany|raw|Query|Exec)\s*\(`), "拼接进 SQL 语句"},
	{"rce", regexp.MustCompile(`(?i)\b(exec|execSync|spawn|execFile|system|popen|subprocess\.(?:run|call|Popen|check_output))\s*\(`), "进入命令执行"},
	{"path", regexp.MustCompile(`(?i)\b(readFile|readFileSync|createReadStream|sendFile|open|os\.Open|ioutil\.ReadFile|FileInputStream)\s*\(`), "进入文件路径"},
	{"ssti", regexp.MustCompile(`(?i)\b(render_template_string|Template|from_string|Engine)\s*\(`), "进入模板渲染"},
	{"redirect", regexp.MustCompile(`(?i)\b(redirect|Redirect|Location)\s*\(`), "进入跳转目标"},
	{"ssrf", regexp.MustCompile(`(?i)\b(fetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|http\.(?:Get|Post|NewRequest)|urlopen)\s*\(`), "进入对外请求 URL"},
	{"deserialize", regexp.MustCompile(`(?i)\b(eval|Function|pickle\.loads|yaml\.load|unserialize|readObject)\s*\(`), "进入反序列化/动态求值"},
	{"html-output", regexp.MustCompile(`(?i)\b(res\.send|res\.write|innerHTML|document\.write|Markup)\s*\(?`), "直接进入 HTML 输出"},
}

// sourcesPerLang lists the request-input reads for each stack, with the capture
// group that names the parameter.
var sourcesPerLang = map[language][]*regexp.Regexp{
	langJS: {
		regexp.MustCompile(`(?i)\breq\s*\.\s*query\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*['"]([^'"]+)['"]\s*\])`),
		regexp.MustCompile(`(?i)\breq\s*\.\s*params\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*['"]([^'"]+)['"]\s*\])`),
		regexp.MustCompile(`(?i)\breq\s*\.\s*body\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*['"]([^'"]+)['"]\s*\])`),
	},
	langPython: {
		regexp.MustCompile(`(?i)request\.args\.get\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`(?i)request\.form\.get\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`(?i)request\.form\[\s*['"]([^'"]+)['"]\s*\]`),
		regexp.MustCompile(`(?i)request\.values\.get\(\s*['"]([^'"]+)['"]`),
	},
	langGo: {
		regexp.MustCompile(`(?i)\.Query\(\s*"([^"]+)"`),
		regexp.MustCompile(`(?i)\.Param\(\s*"([^"]+)"`),
		regexp.MustCompile(`(?i)\.PostForm\(\s*"([^"]+)"`),
	},
	langPHP: {
		regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE)\[\s*['"]([^'"]+)['"]\s*\]`),
	},
	langJava: {
		regexp.MustCompile(`\.getParameter\(\s*"([^"]+)"`),
	},
}

// sanitizers are the mitigations we recognise. If one sits between the source and
// the sink on the same identifier, the hypothesis is dropped silently: noise costs
// the operator more than the missed lead.
// sanitizers are the mitigations we recognise. A parameterised query is the common
// one, and it appears in three shapes: a placeholder followed by a values array, a
// prepare() call, or an explicit cast. Missing them turns every ORM call into a lead.
var sanitizers = regexp.MustCompile(`(?i)parseInt|parseFloat|Number\(|escapeHtml|escape\(|` +
	`htmlspecialchars|shlex\.quote|parameterized|PreparedStatement|` +
	`prepare\s*\(|\?\)?\s*['"]?\s*,\s*\[|\$\d+\)?\s*['"]?\s*,\s*`)

var assignmentRe = map[language]*regexp.Regexp{
	langJS:     regexp.MustCompile(`(?m)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^\n;]+)`),
	langPython: regexp.MustCompile(`(?m)^\s*([A-Za-z_]\w*)\s*=\s*([^\n#]+)`),
	langGo:     regexp.MustCompile(`(?m)\b([A-Za-z_]\w*)\s*:?=\s*([^\n]+)`),
	langPHP:    regexp.MustCompile(`(?m)\$([A-Za-z_]\w*)\s*=\s*([^\n;]+)`),
	langJava:   regexp.MustCompile(`(?m)\b([A-Za-z_]\w*)\s*=\s*([^\n;]+)`),
}

// scanFlow produces sink-* hypotheses for one file.
func scanFlow(lang language, file, src string, routes []Route) []Hypothesis {
	srcPatterns := sourcesPerLang[lang]
	if len(srcPatterns) == 0 {
		return nil
	}
	type tainted struct {
		param string
		line  int
	}
	taintedVars := map[string]tainted{}
	var out []Hypothesis

	// 1) Direct use: sink(... req.query.x ...) on one line.
	for _, s := range sinks {
		for _, m := range s.re.FindAllStringSubmatchIndex(src, -1) {
			lineStart := strings.LastIndexByte(src[:m[0]], '\n') + 1
			lineEnd := strings.IndexByte(src[m[1]:], '\n')
			if lineEnd < 0 {
				lineEnd = len(src)
			} else {
				lineEnd += m[1]
			}
			// Same line only: a ±120 char window silently attributes the previous
			// statement's parameter to this sink.
			window := src[lineStart:lineEnd]
			for _, sp := range srcPatterns {
				sm := sp.FindStringSubmatchIndex(window)
				if sm == nil {
					continue
				}
				param := groupValue(window, sm)
				if param == "" {
					continue
				}
				if sanitizers.MatchString(window) {
					continue
				}
				out = append(out, Hypothesis{
					Kind: "sink", Entry: entryFor(routes, file, lineOf(src, m[0])), Param: param, Sink: s.name,
					Path:       file + ":" + itoa(lineOf(src, m[0])) + " → " + s.name,
					Confidence: "code-only",
					Note:       param + " 未见过滤" + s.why + "(启发式,可能误报)",
					File:       file, Line: lineOf(src, m[0]),
				})
			}
		}
	}

	// 2) Indirect: x = req.query.q; ... sink(x).
	if re := assignmentRe[lang]; re != nil {
		for _, m := range re.FindAllStringSubmatchIndex(src, -1) {
			name := src[m[2]:m[3]]
			rhs := src[m[4]:m[5]]
			for _, sp := range srcPatterns {
				sm := sp.FindStringSubmatchIndex(rhs)
				if sm == nil {
					continue
				}
				param := groupValue(rhs, sm)
				if param == "" {
					continue
				}
				taintedVars[name] = tainted{param: param, line: lineOf(src, m[0])}
			}
		}
	}
	if len(taintedVars) == 0 {
		return out
	}
	names := make([]string, 0, len(taintedVars))
	for n := range taintedVars {
		names = append(names, n)
	}
	sort.Strings(names) // stable output: the same source always produces the same report

	for _, name := range names {
		t := taintedVars[name]
		sinkRe := regexp.MustCompile(`(?m)\b` + regexp.QuoteMeta(name) + `\b`)
		for _, loc := range sinkRe.FindAllStringIndex(src, -1) {
			lineStart := strings.LastIndexByte(src[:loc[0]], '\n') + 1
			lineEnd := strings.IndexByte(src[loc[1]:], '\n')
			if lineEnd < 0 {
				lineEnd = len(src)
			} else {
				lineEnd += loc[1]
			}
			line := src[lineStart:lineEnd]
			for _, s := range sinks {
				if !s.re.MatchString(line) {
					continue
				}
				if sanitizers.MatchString(line) {
					continue
				}
				out = append(out, Hypothesis{
					Kind: "sink", Entry: entryFor(routes, file, lineOf(src, loc[0])), Param: t.param, Sink: s.name,
					Path:       file + ":" + itoa(t.line) + " → " + s.name + ":" + itoa(lineOf(src, loc[0])),
					Confidence: "code-only",
					Note:       name + " 来自 " + t.param + ",未见过滤" + s.why + "(启发式,可能误报)",
					File:       file, Line: lineOf(src, loc[0]),
				})
			}
		}
	}
	return out
}

// entryFor finds the route that contains a given line: the declaration closest
// ABOVE it, not the last one in the file. Getting this wrong attributes every lead
// to whichever route happens to sit at the bottom of the file.
func entryFor(routes []Route, file string, line int) string {
	best := ""
	bestLine := -1
	for _, r := range routes {
		if r.File != file || r.Line <= 0 {
			continue
		}
		if r.Line <= line && r.Line > bestLine {
			bestLine = r.Line
			best = r.Method + " " + r.Path
		}
	}
	if best == "" && len(routes) > 0 {
		// A sink above the first route is still in that route's file; do not invent
		// an entry, leave it empty so the engine can skip it.
		return ""
	}
	return best
}
func groupValue(src string, idx []int) string {
	for i := 2; i+1 < len(idx); i += 2 {
		if idx[i] >= 0 && idx[i+1] > idx[i] {
			return src[idx[i]:idx[i+1]]
		}
	}
	return ""
}

func itoa(n int) string {
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
