package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubConfig builds a HandConfig that re-executes this test binary as a fake MCP
// server (the classic TestHelperProcess pattern). It keeps the test hermetic: no
// node, no Fairy, no Verdex.
func stubConfig(t *testing.T, mode string) HandConfig {
	t.Helper()
	return HandConfig{
		Name: "stub-" + mode,
		Cmd:  os.Args[0],
		Args: []string{"-test.run=^TestYoukaiMCPStub$", "--", mode},
		Env:  []string{"YOUKAI_MCP_STUB=1", "YOUKAI_MCP_STUB_MODE=" + mode},
	}
}

func dialStub(t *testing.T, mode string) *Client {
	t.Helper()
	c, err := Dial(context.Background(), stubConfig(t, mode))
	if err != nil {
		t.Fatalf("Dial(%s): %v", mode, err)
	}
	c.DefaultCallTimeout = 5 * time.Second
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestYoukaiMCPStub is the fake MCP server. It only acts when the env var is set,
// so it is inert during normal test runs.
func TestYoukaiMCPStub(t *testing.T) {
	if os.Getenv("YOUKAI_MCP_STUB") != "1" {
		return
	}
	mode := os.Getenv("YOUKAI_MCP_STUB_MODE")
	if mode == "die_on_init" {
		os.Exit(4)
	}

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	enc := json.NewEncoder(os.Stdout)

	write := func(id *json.RawMessage, result any) {
		m := map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
		_ = enc.Encode(m)
	}
	writeText := func(id *json.RawMessage, text string) {
		write(id, map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
		})
	}

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req struct {
			ID     *json.RawMessage `json:"id"`
			Method string           `json:"method"`
			Params json.RawMessage  `json:"params"`
		}
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		if req.ID == nil {
			continue // notification
		}
		switch req.Method {
		case "initialize":
			write(req.ID, map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "stub", "version": "0.0.0"},
			})
		case "tools/list":
			write(req.ID, map[string]any{"tools": []map[string]any{
				{"name": "echo", "description": "echo args back"},
				{"name": "hang", "description": "never answers"},
				{"name": "die", "description": "kills the server"},
				{"name": "junk", "description": "prints junk first"},
				{"name": "notify", "description": "emits a notification"},
				{"name": "fail", "description": "reports a tool error"},
			}})
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(req.Params, &p)
			switch p.Name {
			case "echo":
				writeText(req.ID, string(p.Arguments))
			case "hang":
				// Deliberately no answer, but keep serving: the client must time
				// out on this call without wedging its other work.
			case "die":
				os.Exit(3)
			case "junk":
				fmt.Fprintln(os.Stdout, "this is not json {")
				writeText(req.ID, `{"ok":true}`)
			case "notify":
				_ = enc.Encode(map[string]any{
					"jsonrpc": "2.0",
					"method":  "notifications/progress",
					"params":  map[string]any{"done": true},
				})
				writeText(req.ID, `{"ok":true}`)
			case "fail":
				write(req.ID, map[string]any{
					"isError": true,
					"content": []map[string]any{{"type": "text", "text": "boom: bad args"}},
				})
			default:
				_ = enc.Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"error":   map[string]any{"code": -32601, "message": "unknown tool " + p.Name},
				})
			}
		}
	}
	os.Exit(0)
}

func TestDialHandshakeAndListTools(t *testing.T) {
	c := dialStub(t, "normal")

	info := c.ServerInfo()
	if info.ServerInfo.Name != "stub" {
		t.Fatalf("serverInfo.name = %q, want stub", info.ServerInfo.Name)
	}
	if info.ProtocolVersion != "2024-11-05" {
		t.Fatalf("protocolVersion = %q", info.ProtocolVersion)
	}

	tools, err := c.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"echo", "hang", "die"} {
		if !names[want] {
			t.Fatalf("tools/list missing %q (got %v)", want, names)
		}
	}

	ok, err := c.HasTool(context.Background(), "echo")
	if err != nil || !ok {
		t.Fatalf("HasTool(echo) = %v, %v", ok, err)
	}
}

func TestCallToolRoundTrip(t *testing.T) {
	c := dialStub(t, "normal")

	res, err := c.CallTool(context.Background(), "echo", map[string]any{
		"url": "http://lab.invalid/.git/config",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", res.Text())
	}
	if !strings.Contains(res.Text(), "lab.invalid") {
		t.Fatalf("echo payload lost: %q", res.Text())
	}
	if len(res.Raw) == 0 {
		t.Fatal("raw result was not preserved")
	}

	var decoded struct {
		URL string `json:"url"`
	}
	if err := res.JSON(&decoded); err != nil {
		t.Fatalf("result JSON: %v", err)
	}
	if decoded.URL != "http://lab.invalid/.git/config" {
		t.Fatalf("round trip mangled args: %+v", decoded)
	}
}

func TestCallToolReportsToolError(t *testing.T) {
	c := dialStub(t, "normal")
	res, err := c.CallTool(context.Background(), "fail", nil)
	if err != nil {
		t.Fatalf("CallTool(fail) should not be a transport error: %v", err)
	}
	if !res.IsError {
		t.Fatal("isError was not preserved from the hand")
	}
	if !strings.Contains(res.Text(), "boom") {
		t.Fatalf("error text lost: %q", res.Text())
	}
}

func TestCallToolTimeoutKeepsClientUsable(t *testing.T) {
	c := dialStub(t, "normal")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.CallTool(ctx, "hang", nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("timeout took %v, expected ~150ms", elapsed)
	}

	// The timed-out id must not poison the client.
	res, err := c.CallTool(context.Background(), "echo", map[string]any{"n": 1})
	if err != nil {
		t.Fatalf("client unusable after timeout: %v", err)
	}
	if !strings.Contains(res.Text(), `"n":1`) {
		t.Fatalf("unexpected payload after timeout: %q", res.Text())
	}
}

func TestProcessExitFailsPendingCall(t *testing.T) {
	c := dialStub(t, "normal")

	done := make(chan error, 1)
	go func() {
		_, err := c.CallTool(context.Background(), "die", nil)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error when the hand dies mid-call")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CallTool hung after the hand process exited")
	}

	// Later calls must fail fast rather than hang.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.CallTool(ctx, "echo", nil); err == nil {
		t.Fatal("expected error calling a dead hand")
	}
}

func TestUnparseableStdoutIsTolerated(t *testing.T) {
	c := dialStub(t, "normal")
	res, err := c.CallTool(context.Background(), "junk", nil)
	if err != nil {
		t.Fatalf("junk line broke the client: %v", err)
	}
	if !strings.Contains(res.Text(), "ok") {
		t.Fatalf("unexpected payload: %q", res.Text())
	}
	if !strings.Contains(c.StderrTail(), "unparseable stdout line") {
		t.Fatalf("junk line was not logged; stderr=%q", c.StderrTail())
	}
}

func TestNotificationCallback(t *testing.T) {
	var mu sync.Mutex
	var got []string

	cfg := stubConfig(t, "normal")
	c, err := DialWith(context.Background(), cfg, DialOptions{
		Notify: func(method string, _ json.RawMessage) {
			mu.Lock()
			got = append(got, method)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("DialWith: %v", err)
	}
	defer c.Close()

	if _, err := c.CallTool(context.Background(), "notify", nil); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			mu.Lock()
			defer mu.Unlock()
			if got[0] != "notifications/progress" {
				t.Fatalf("notification method = %q", got[0])
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("notification callback never fired")
}

func TestDialFailsWhenHandDiesImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := Dial(ctx, stubConfig(t, "die_on_init"))
	if err == nil {
		t.Fatal("expected handshake failure for a hand that exits immediately")
	}
	if !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("unexpected error shape: %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	c, err := Dial(context.Background(), stubConfig(t, "normal"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := c.CallTool(context.Background(), "echo", nil); err == nil {
		t.Fatal("expected error calling a closed client")
	}
}

func TestHandConfigValidate(t *testing.T) {
	if err := (HandConfig{Name: "x", Cmd: "node"}).Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := (HandConfig{Name: "x"}).Validate(); err == nil {
		t.Fatal("empty cmd accepted")
	}
}
