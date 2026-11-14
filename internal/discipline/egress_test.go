package discipline

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoEgressOutsideTheGuard is the static half of the spine.
//
// The discipline promise is not "we try to route through Guard"; it is "there is
// no other way out". This test walks every non-test Go file in the repo and fails
// on the constructions that would create a second egress path.
//
// Allowed exceptions:
//   - internal/discipline itself (that IS the egress)
//   - *_test.go anywhere (tests may stand up httptest targets)
//   - internal/api (it serves HTTP inbound; httptest/inbound Server types are
//     fine, and it is checked to never construct an outbound client)
func TestNoEgressOutsideTheGuard(t *testing.T) {
	root := repoRoot(t)
	forbiddenIn := map[string]string{
		"http.Client":        "constructs an outbound HTTP client",
		"http.DefaultClient": "uses the process-wide egress client",
		"http.Get":           "sends a request",
		"http.Post":          "sends a request",
		"http.Head":          "sends a request",
		"http.PostForm":      "sends a request",
		"http.NewRequest":    "builds an outbound request",
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == ".pgsql" || name == "lab" ||
				name == "vendor" || name == ".youkai" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "internal/discipline/") {
			return nil // the egress itself
		}
		// One documented exception: the LLM planner talks to a model endpoint the
		// operator configured. That is not a target, it must never receive target
		// traffic, and it cannot be authorised by a scope passport. It may build a
		// client and a request, but it may not use the convenience senders.
		plannerException := strings.HasPrefix(rel, "internal/planner/")

		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("%s: parse: %v", rel, perr)
			return nil
		}
		// Raw sockets are the other way out. The only exception is the CDP client's
		// WebSocket handshake, and that file refuses any non-loopback endpoint
		// before it dials.
		rawDialAllowed := rel == "internal/web/ws.go"
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && !rawDialAllowed {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "net" {
					switch sel.Sel.Name {
					case "Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP":
						t.Errorf("%s: net.%s opens a raw socket - only internal/discipline may leave the machine",
							rel, sel.Sel.Name)
					}
				}
			}
			return true
		})
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "http" {
				return true
			}
			call := "http." + sel.Sel.Name
			switch call {
			case "http.Client", "http.DefaultClient", "http.Get", "http.Post",
				"http.Head", "http.PostForm", "http.NewRequest":
				if plannerException && (call == "http.Client" || call == "http.NewRequest") {
					return true
				}
				t.Errorf("%s: %s %s - only internal/discipline may leave the machine",
					rel, call, forbiddenIn[call])
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestScopeIsOnlyBuiltThroughValidate guards against a zero-scope bypass: the
// guard constructor must refuse a passport that authorises nothing.
func TestGuardRefusesUnvalidatedScope(t *testing.T) {
	aud := &memAuditor{}
	if _, err := NewGuard(&Scope{}, "x", aud); err == nil {
		t.Fatal("NewGuard accepted an empty passport")
	}
	if _, err := NewGuard(nil, "x", aud); err == nil {
		t.Fatal("NewGuard accepted a nil passport")
	}
	if _, err := NewGuard(NewScope(Scope{Include: []string{"x"}, Basis: "long enough basis", Operator: "t"}), "x", nil); err == nil {
		t.Fatal("NewGuard accepted a nil auditor (no audit, no request)")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test directory")
		}
		dir = parent
	}
}

// TestReportPackageCannotReachTheNetwork pins the promise the report package makes
// in its doc comment: it is a pure projection. If it could import the guard or the
// web package, "reading the ledger" would quietly become "asking the target again",
// and a snapshot would stop being reproducible.
func TestReportPackageCannotReachTheNetwork(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "report")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read report dir: %v", err)
	}
	banned := []string{
		"youkai/internal/gate",
		"youkai/internal/discipline",
		"youkai/internal/web",
		"youkai/internal/binary",
		"youkai/internal/accounts",
		"youkai/internal/runtime",
		"net/http",
		"net",
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		text := string(src)
		for _, pkg := range banned {
			if strings.Contains(text, `"`+pkg+`"`) {
				t.Errorf("internal/report/%s imports %q; the report must stay a pure ledger projection",
					entry.Name(), pkg)
			}
		}
	}
}
