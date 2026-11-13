package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// Version is reported to hands as clientInfo.version.
const Version = "0.1.0"

// protocolVersion is the MCP revision youkai speaks. Both Fairy and Verdex
// answer with it (verified against the real hands on 2026-11-13).
const protocolVersion = "2024-11-05"

const (
	// maxLineBytes bounds a single stdout line. Hands are local and trusted to a
	// degree, but a malformed/huge line must not OOM the brain.
	maxLineBytes = 16 << 20
	// defaultCallTimeout applies when the caller's context carries no deadline.
	defaultCallTimeout = 120 * time.Second
	// closeGrace is how long Close waits for a hand to exit politely.
	closeGrace = 2 * time.Second
)

// ErrClosed is returned for calls made on, or interrupted by, a closed client.
var ErrClosed = errors.New("mcp: client closed")

// ErrProcExit is wrapped by errors caused by the hand process exiting.
var ErrProcExit = errors.New("mcp: hand process exited")

// DialOptions tunes an optional bell/whistle. Zero value is fine.
type DialOptions struct {
	// ClientName identifies youkai to the hand (default "youkai").
	ClientName string
	// Stderr receives the hand's stderr. Default: a bounded in-memory ring
	// buffer readable via StderrTail().
	Stderr io.Writer
	// Notify is called for every notification the hand emits (no id). It runs on
	// the reader goroutine, so it must not block.
	Notify func(method string, params json.RawMessage)
}

// Client is a connected hand.
//
// Concurrency: CallTool/ListTools are safe to call from many goroutines; writes
// are serialised and responses are routed by JSON-RPC id.
type Client struct {
	name string
	cfg  HandConfig

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser

	writeMu     sync.Mutex
	stdinClosed bool

	mu       sync.Mutex
	nextID   int64
	pending  map[int64]chan rawMsg
	closed   bool
	closeErr error

	notifyMu sync.Mutex
	notify   func(method string, params json.RawMessage)

	initMu sync.Mutex
	init   InitializeResult

	stderr io.Writer
	ring   *ringWriter

	done     chan struct{} // closed when the reader goroutine finishes
	waitDone chan struct{} // closed when the process has been reaped
	waitErr  error

	closeOnce sync.Once

	// DefaultCallTimeout is the per-call timeout used when the caller's context
	// has no deadline. Exported so tests can shorten it.
	DefaultCallTimeout time.Duration
}

// Dial starts the hand described by cfg and performs the MCP handshake.
func Dial(ctx context.Context, cfg HandConfig) (*Client, error) {
	return DialWith(ctx, cfg, DialOptions{})
}

// DialWith is Dial with options.
func DialWith(ctx context.Context, cfg HandConfig, opts DialOptions) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Cmd == "" {
		cfg.Cmd = "node"
	}
	if opts.ClientName == "" {
		opts.ClientName = "youkai"
	}

	cmd := exec.Command(cfg.Cmd, cfg.Args...)
	if cfg.Cwd != "" {
		cmd.Dir = cfg.Cwd
	}
	if len(cfg.Env) > 0 {
		cmd.Env = append(os.Environ(), cfg.Env...)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp %s: stdin pipe: %w", cfg.Name, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp %s: stdout pipe: %w", cfg.Name, err)
	}

	c := &Client{
		name:               cfg.Name,
		cfg:                cfg,
		cmd:                cmd,
		stdin:              stdin,
		stdout:             stdout,
		pending:            make(map[int64]chan rawMsg),
		notify:             opts.Notify,
		done:               make(chan struct{}),
		waitDone:           make(chan struct{}),
		DefaultCallTimeout: defaultCallTimeout,
	}
	if opts.Stderr != nil {
		c.stderr = opts.Stderr
	} else {
		c.ring = newRingWriter(64 << 10)
		c.stderr = c.ring
	}
	cmd.Stderr = c.stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcp %s: start %q: %w", cfg.Name, cfg.Cmd, err)
	}

	go func() {
		c.waitErr = cmd.Wait()
		close(c.waitDone)
	}()
	go c.readLoop()

	if err := c.initialize(ctx, opts.ClientName); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("mcp %s: handshake: %w", cfg.Name, err)
	}
	return c, nil
}

// Name is the logical hand name.
func (c *Client) Name() string { return c.name }

// Config is the launch config this client was dialled with.
func (c *Client) Config() HandConfig { return c.cfg }

// ServerInfo is what the hand reported during the handshake.
func (c *Client) ServerInfo() InitializeResult {
	c.initMu.Lock()
	defer c.initMu.Unlock()
	return c.init
}

// StderrTail returns the captured stderr when no explicit writer was supplied.
func (c *Client) StderrTail() string {
	if c.ring == nil {
		return ""
	}
	return c.ring.String()
}

// PID is the hand's process id, or 0 when it has exited.
func (c *Client) PID() int {
	if c.cmd == nil || c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

func (c *Client) initialize(ctx context.Context, clientName string) error {
	params := map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    clientName,
			"version": Version,
		},
	}
	m, err := c.call(ctx, "initialize", params)
	if err != nil {
		return err
	}
	if m.Error != nil {
		return m.Error
	}
	var res InitializeResult
	if len(m.Result) > 0 {
		if err := json.Unmarshal(m.Result, &res); err != nil {
			return fmt.Errorf("decode initialize result: %w", err)
		}
	}
	c.initMu.Lock()
	c.init = res
	c.initMu.Unlock()

	return c.writeMsg(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
}

// ListTools returns the hand's tool inventory.
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	m, err := c.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	if m.Error != nil {
		return nil, m.Error
	}
	var res toolListResult
	if err := json.Unmarshal(m.Result, &res); err != nil {
		return nil, fmt.Errorf("decode tools/list: %w", err)
	}
	return res.Tools, nil
}

// HasTool reports whether the hand advertises name.
func (c *Client) HasTool(ctx context.Context, name string) (bool, error) {
	tools, err := c.ListTools(ctx)
	if err != nil {
		return false, err
	}
	for _, t := range tools {
		if t.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// CallTool invokes one tool. A hand-reported tool failure is NOT an error here:
// it comes back as ToolResult.IsError so the caller keeps the raw evidence. Only
// transport/protocol failures are returned as errors.
func (c *Client) CallTool(ctx context.Context, name string, args any) (ToolResult, error) {
	if args == nil {
		args = map[string]any{}
	}
	m, err := c.call(ctx, "tools/call", map[string]any{
		"name":      name,
		"arguments": args,
	})
	if err != nil {
		return ToolResult{}, err
	}
	if m.Error != nil {
		return ToolResult{}, m.Error
	}
	var tr ToolResult
	if len(m.Result) > 0 {
		if err := json.Unmarshal(m.Result, &tr); err != nil {
			return ToolResult{}, fmt.Errorf("decode tools/call result: %w", err)
		}
	}
	tr.Raw = append(json.RawMessage(nil), m.Result...)
	return tr, nil
}

// Close shuts the hand down: close stdin, give it closeGrace to leave, then kill.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.stdinClosed = true
		c.mu.Unlock()

		if c.stdin != nil {
			_ = c.stdin.Close()
		}
		select {
		case <-c.waitDone:
			// exited on its own
		case <-time.After(closeGrace):
			if c.cmd != nil && c.cmd.Process != nil {
				_ = c.cmd.Process.Kill()
			}
			select {
			case <-c.waitDone:
			case <-time.After(closeGrace):
				err = fmt.Errorf("mcp %s: process did not exit after kill", c.name)
			}
		}
		if c.stdout != nil {
			_ = c.stdout.Close()
		}
		c.shutdown(ErrClosed)
	})
	return err
}

// call performs one JSON-RPC round trip.
func (c *Client) call(ctx context.Context, method string, params any) (rawMsg, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := c.DefaultCallTimeout
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}
	if _, ok := ctx.Deadline(); !ok && timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	id := c.allocID()
	ch := make(chan rawMsg, 1)

	c.mu.Lock()
	if c.closed {
		err := c.closeErr
		c.mu.Unlock()
		if err == nil {
			err = ErrClosed
		}
		return rawMsg{}, err
	}
	c.pending[id] = ch
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	if err := c.writeMsg(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}); err != nil {
		return rawMsg{}, err
	}

	select {
	case m := <-ch:
		return m, nil
	case <-ctx.Done():
		// The response may have landed in the same instant.
		select {
		case m := <-ch:
			return m, nil
		default:
		}
		return rawMsg{}, fmt.Errorf("mcp %s: %s: %w", c.name, method, ctx.Err())
	case <-c.done:
		// Same race discipline: prefer a response that already arrived.
		select {
		case m := <-ch:
			return m, nil
		default:
		}
		return rawMsg{}, fmt.Errorf("mcp %s: %s: %w", c.name, method, c.exitError())
	}
}

func (c *Client) exitError() error {
	select {
	case <-c.waitDone:
		if c.waitErr != nil {
			return fmt.Errorf("%w: %v", ErrProcExit, c.waitErr)
		}
		return ErrProcExit
	default:
		return ErrProcExit
	}
}

func (c *Client) allocID() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	return c.nextID
}

func (c *Client) writeMsg(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("mcp %s: encode: %w", c.name, err)
	}
	b = append(b, '\n')

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.stdinClosed {
		return fmt.Errorf("mcp %s: write: %w", c.name, ErrClosed)
	}
	if _, err := c.stdin.Write(b); err != nil {
		return fmt.Errorf("mcp %s: write: %w", c.name, err)
	}
	return nil
}

// readLoop reads newline-delimited JSON-RPC from the hand until stdout closes.
func (c *Client) readLoop() {
	defer close(c.done)
	sc := bufio.NewScanner(c.stdout)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m rawMsg
		if err := json.Unmarshal(line, &m); err != nil {
			// A hand that prints junk to stdout must not take the brain down.
			// Record and move on; the call timeout covers a lost response.
			c.logStderrNote("unparseable stdout line (%d bytes): %v", len(line), err)
			continue
		}
		c.dispatch(m)
	}
	if err := sc.Err(); err != nil {
		c.logStderrNote("stdout scan ended: %v", err)
	}
	c.shutdown(fmt.Errorf("mcp %s: stdout closed", c.name))
}

// logStderrNote writes a diagnostic into the same sink as hand stderr so it
// shows up in one place when a run goes sideways.
func (c *Client) logStderrNote(format string, args ...any) {
	if c.stderr == nil {
		return
	}
	fmt.Fprintf(c.stderr, "[youkai] "+format+"\n", args...)
}

func (c *Client) dispatch(m rawMsg) {
	if m.Method != "" {
		if m.ID != nil {
			// Server->client request. youkai implements no client-side MCP
			// features (sampling/roots), so refuse cleanly instead of hanging
			// the hand.
			_ = c.writeMsg(map[string]any{
				"jsonrpc": "2.0",
				"id":      *m.ID,
				"error": map[string]any{
					"code":    -32601,
					"message": "method not supported by youkai: " + m.Method,
				},
			})
			return
		}
		c.notifyMu.Lock()
		cb := c.notify
		c.notifyMu.Unlock()
		if cb != nil {
			cb(m.Method, m.Params)
		}
		return
	}
	if m.ID == nil {
		return
	}
	id, ok := parseID(*m.ID)
	if !ok {
		c.logStderrNote("response with unusable id: %s", string(*m.ID))
		return
	}
	c.mu.Lock()
	ch := c.pending[id]
	delete(c.pending, id)
	c.mu.Unlock()
	if ch == nil {
		return // late response after timeout: drop it
	}
	ch <- m
}

// shutdown marks the client dead so no caller waits forever.
func (c *Client) shutdown(cause error) {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.closeErr = cause
	}
	c.mu.Unlock()
}

func parseID(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// ringWriter keeps the last max bytes written to it.
type ringWriter struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func newRingWriter(max int) *ringWriter {
	return &ringWriter{max: max}
}

func (r *ringWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.max {
		r.buf = r.buf[len(r.buf)-r.max:]
	}
	return len(p), nil
}

func (r *ringWriter) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.buf)
}
