// Package whitebox reads application source code and turns it into hypotheses.
//
// What it is: a map. It finds routes, follows parameters toward dangerous sinks,
// and notices which routes look unprotected. Every output is a HYPOTHESIS with
// confidence "code-only" - a guess about where to look, not a vulnerability.
//
// What it is not: a scanner. It sends no requests, executes nothing, and never
// upgrades its own output. A hypothesis becomes a candidate only when a black-box
// probe actually hits, and becomes verified only when a human says so.
//
// It also refuses to keep what it reads: the ledger stores file:line, symbol names
// and a one-line flow summary - never the source text, never a secret value.
package whitebox

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Limits keep a careless `code_ingest .` from walking a whole disk.
const (
	maxFiles      = 4000
	maxFileBytes  = 512 << 10
	maxRoutes     = 400
	maxHypotheses = 200
)

// Route is one code-side entry point.
type Route struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Handler   string `json:"handler,omitempty"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Auth      bool   `json:"auth"`
	Framework string `json:"framework"`
}

// Hypothesis is a lead: "this input may reach that sink".
type Hypothesis struct {
	Kind       string `json:"kind"`  // sink-* / missing-authz
	Entry      string `json:"entry"` // "GET /search"
	Param      string `json:"param"` // "q"
	Sink       string `json:"sink"`  // sql-concat / rce / path / ssti / redirect / ssrf / deserialize / html-output
	Path       string `json:"path"`  // "routes.js:12 → db.query:40"
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
	File       string `json:"file"`
	Line       int    `json:"line"`
}

// Report is what one ingest produced.
type Report struct {
	Root       string       `json:"root"`
	Files      int          `json:"files"`
	Lines      int          `json:"lines"`
	Routes     []Route      `json:"routes"`
	Hypotheses []Hypothesis `json:"hypotheses"`
	Warnings   []string     `json:"warnings,omitempty"`
	Skipped    []string     `json:"skipped,omitempty"`
}

// language is the small set of stacks this build understands.
type language int

const (
	langUnknown language = iota
	langJS
	langPython
	langGo
	langPHP
	langJava
)

func (l language) String() string {
	switch l {
	case langJS:
		return "javascript"
	case langPython:
		return "python"
	case langGo:
		return "go"
	case langPHP:
		return "php"
	case langJava:
		return "java"
	}
	return "unknown"
}

func languageOf(path string, head []byte) language {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".mjs", ".cjs", ".ts":
		return langJS
	case ".py":
		return langPython
	case ".go":
		return langGo
	case ".php":
		return langPHP
	case ".java":
		return langJava
	}
	return langUnknown
}

// Ingest walks a directory and returns the map. It never follows symlinks out of
// the tree and never leaves the directory it was given.
func Ingest(root string) (Report, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Report{}, fmt.Errorf("whitebox: resolve %s: %w", root, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Report{}, fmt.Errorf("whitebox: %w", err)
	}
	if !info.IsDir() {
		return Report{}, fmt.Errorf("whitebox: %s is not a directory", abs)
	}
	rep := Report{Root: abs}

	err = filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			rep.Warnings = append(rep.Warnings, "跳过 "+path+":"+err.Error())
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			// Vendor trees are noise and enormous; node_modules hides real code.
			if name == "node_modules" || name == "vendor" || name == ".git" || name == "dist" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		if rep.Files >= maxFiles {
			return filepath.SkipAll
		}
		if !d.Type().IsRegular() {
			return nil
		}
		lang := languageOf(path, nil)
		if lang == langUnknown {
			return nil
		}
		fi, err := d.Info()
		if err != nil || fi.Size() > maxFileBytes {
			rep.Skipped = append(rep.Skipped, path+"(过大或不可读)")
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			rep.Skipped = append(rep.Skipped, path+"("+err.Error()+")")
			return nil
		}
		rel, _ := filepath.Rel(abs, path)
		rel = filepath.ToSlash(rel)
		rep.Files++
		src := string(data)
		rep.Lines += strings.Count(src, "\n") + 1

		routes := scanRoutes(lang, rel, src)
		rep.Routes = append(rep.Routes, routes...)
		rep.Hypotheses = append(rep.Hypotheses, scanFlow(lang, rel, src, routes)...)
		rep.Hypotheses = append(rep.Hypotheses, scanAuthz(lang, rel, src, routes)...)
		if len(rep.Routes) > maxRoutes {
			rep.Routes = rep.Routes[:maxRoutes]
			rep.Warnings = append(rep.Warnings, "路由超过上限,已截断")
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	rep.Hypotheses = dedupeHypotheses(rep.Hypotheses)
	if len(rep.Hypotheses) > maxHypotheses {
		rep.Hypotheses = rep.Hypotheses[:maxHypotheses]
		rep.Warnings = append(rep.Warnings, "假设超过上限,已截断")
	}
	sort.SliceStable(rep.Routes, func(i, j int) bool {
		if rep.Routes[i].Path != rep.Routes[j].Path {
			return rep.Routes[i].Path < rep.Routes[j].Path
		}
		return rep.Routes[i].Method < rep.Routes[j].Method
	})
	return rep, nil
}

func dedupeHypotheses(in []Hypothesis) []Hypothesis {
	seen := map[string]bool{}
	out := in[:0]
	for _, h := range in {
		key := h.Kind + "|" + h.Entry + "|" + h.Param + "|" + h.Sink + "|" + h.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out
}

// lineOf turns a byte offset into a 1-based line number.
func lineOf(src string, off int) int {
	if off <= 0 {
		return 1
	}
	if off > len(src) {
		off = len(src)
	}
	return strings.Count(src[:off], "\n") + 1
}

// snippetAt returns a short, source-free description of what is at an offset:
// the identifier immediately before it. Nothing from the file body is kept.
func symbolBefore(src string, off int) string {
	start := off
	for start > 0 {
		c := src[start-1]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' {
			start--
			continue
		}
		break
	}
	sym := src[start:off]
	if len(sym) > 40 {
		sym = sym[len(sym)-40:]
	}
	return sym
}
