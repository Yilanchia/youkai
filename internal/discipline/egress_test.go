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
