package binary

import (
	"os"
	"strings"
	"testing"
)

// TestPackageStaysOfflineAndNonExecuting is a regression guard for the hard
// rules: this package must never grow an HTTP client, must never run a sample,
// and must only start whitelisted tools through the bounded runner.
func TestPackageStaysOfflineAndNonExecuting(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var sources strings.Builder
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(data)
		sources.WriteString(src)
		forbidden := []string{
			`"net/http"`,
			`"net"`,
			"net.Dial",
			"http.Get",
			"http.Post",
			"exec.Command(",
			"os.StartProcess",
			"syscall.Exec",
		}
		for _, needle := range forbidden {
			if strings.Contains(src, needle) {
				t.Errorf("%s contains forbidden construct %q", name, needle)
			}
		}
	}
	if !strings.Contains(sources.String(), "exec.CommandContext") {
		t.Error("expected the bounded tool runner to exist")
	}
	if strings.Contains(sources.String(), "Execute()") {
		t.Error("unexpected generic execute helper")
	}
}
