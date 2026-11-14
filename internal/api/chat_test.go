package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"youkai/internal/ledger"
)

// TestChatHistoryOverHTTP: what the operator typed is still there after a reload,
// and it is the ledger that holds it (not the browser).
func TestChatHistoryOverHTTP(t *testing.T) {
	f := newFixture(t, "")
	path := fmt.Sprintf("/api/engagements/%d/chat", f.eng.ID)

	code, body := f.do(t, http.MethodGet, path, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("history: %d %v", code, body)
	}
	if n := len(body["messages"].([]any)); n != 0 {
		t.Fatalf("fresh engagement has %d messages", n)
	}

	if _, err := f.store.AppendChat(context.Background(), f.eng.ID, "user", "你好", nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := f.store.AppendChat(context.Background(), f.eng.ID, "assistant", "在", []map[string]any{{"type": "note", "text": "x"}}); err != nil {
		t.Fatalf("append: %v", err)
	}

	code, body = f.do(t, http.MethodGet, path, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("history: %d %v", code, body)
	}
	msgs := body["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("history = %d messages, want 2", len(msgs))
	}
	first := msgs[0].(map[string]any)
	if first["role"] != "user" || first["content"] != "你好" {
		t.Fatalf("first message = %v", first)
	}
}

// TestRejectClosesTheStep: refusing is a recorded act, not a no-op.
func TestRejectClosesTheStep(t *testing.T) {
	f := newFixture(t, "")
	it, _, err := f.store.EnsureIntent(context.Background(), f.eng.ID, ledger.IntentSpec{
		Capability: "param", Args: map[string]any{"url": "http://127.0.0.1:9/s?q=1", "param": "q"},
		Tier: 2, RequiresApproval: true,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = f.store.SetIntentStatus(context.Background(), f.eng.ID, it.ID, ledger.StatusNeedsApproval)

	code, body := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/intents/%d/reject", f.eng.ID, it.ID),
		map[string]any{"operator": "alice", "reason": "太吵了"}, nil)
	if code != http.StatusOK {
		t.Fatalf("reject = %d %v", code, body)
	}
	got, err := f.store.Intent(context.Background(), f.eng.ID, it.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Status != ledger.StatusBlocked {
		t.Fatalf("status after reject = %q", got.Status)
	}
	if f.disp.calls != 0 {
		t.Fatal("a rejected step was dispatched")
	}
}

// TestChatPathCannotApprove is the ADR-006 red line as a test: the model's code
// path must not contain a way to approve or execute. This reads the sources, so it
// fails the moment someone wires the conversation to the approval table.
func TestChatPathCannotApprove(t *testing.T) {
	banned := []string{"ApproveIntent", "ConsumeApproval", "executeIntent", "approveIntent"}
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	files := []string{
		filepath.Join(dir, "chat.go"),
		filepath.Join(dir, "..", "planner", "chat.go"),
		filepath.Join(dir, "..", "..", "web", "chat.js"),
	}
	for _, name := range files {
		src := readFileOrFail(t, name)
		for _, b := range banned {
			if contains(src, b) {
				t.Fatalf("%s mentions %s: the conversational path must not be able to approve", name, b)
			}
		}
	}
}

func readFileOrFail(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func contains(h, n string) bool { return strings.Contains(h, n) }

var _ = time.Now
