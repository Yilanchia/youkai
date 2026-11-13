// Package mcp implements the minimal MCP (Model Context Protocol) client that
// youkai needs in order to drive its two "hands": Fairy (web) and Verdex
// (binary). It speaks JSON-RPC 2.0, newline-delimited, over a child process's
// stdin/stdout. Nothing else.
//
// Design rule that matters more than any detail here: this package moves bytes
// between youkai and a hand. It never interprets a hand's result into a security
// conclusion - that is the loop's job (see internal/loop/facts.go), and the
// interpretation is deterministic and reviewable.
package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// HandConfig describes how to launch one MCP server subprocess.
//
// It is the on-disk shape of an entry in .youkai/hands.json:
//
//	{ "fairy": {"cwd": "D:\\fairy_fairy", "cmd": "node", "args": ["src/cli.js","mcp"]} }
type HandConfig struct {
	// Name is the logical hand name ("fairy", "verdex"). Not serialised; the
	// name is the JSON key in hands.json.
	Name string `json:"-"`
	// Cwd is the working directory the hand expects (Fairy: the Fairy checkout;
	// Verdex: the Verdex checkout).
	Cwd string `json:"cwd"`
	// Cmd is the executable. Defaults to "node".
	Cmd string `json:"cmd"`
	// Args are passed verbatim after Cmd.
	Args []string `json:"args"`
	// Env is an optional "K=V" list appended to the inherited environment.
	Env []string `json:"env,omitempty"`
}

// Validate rejects configs that could not possibly start a hand.
func (c HandConfig) Validate() error {
	if strings.TrimSpace(c.Cmd) == "" {
		return fmt.Errorf("hand %q: cmd is empty", c.Name)
	}
	return nil
}

// Tool is one entry from tools/list.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ToolContent is one element of a tools/call result content array.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ToolResult is the verbatim result of tools/call.
//
// Youkai deliberately keeps the raw JSON: Fairy and Verdex have different result
// shapes and this client must not hardcode either. Text() is a convenience for
// the common single-text-content case.
type ToolResult struct {
	Content []ToolContent `json:"content,omitempty"`
	IsError bool          `json:"isError,omitempty"`
	// Raw is the untouched JSON of the "result" member.
	Raw json.RawMessage `json:"-"`
}

// Text joins the text content blocks. Hands almost always answer with exactly
// one block of JSON-as-text.
func (r ToolResult) Text() string {
	if len(r.Content) == 0 {
		return ""
	}
	if len(r.Content) == 1 {
		return r.Content[0].Text
	}
	parts := make([]string, 0, len(r.Content))
	for _, c := range r.Content {
		parts = append(parts, c.Text)
	}
	return strings.Join(parts, "\n")
}

// JSON decodes the text payload into v. Hands return JSON-as-text; this is the
// only decoding the client does on their behalf.
func (r ToolResult) JSON(v any) error {
	t := strings.TrimSpace(r.Text())
	if t == "" {
		return fmt.Errorf("tool result has no text content")
	}
	if err := json.Unmarshal([]byte(t), v); err != nil {
		return fmt.Errorf("tool result is not JSON: %w", err)
	}
	return nil
}

// RPCError is a JSON-RPC error object returned by a hand.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	if e == nil {
		return "<nil rpc error>"
	}
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// rawMsg is the envelope read off stdout. Every field is optional because a
// notification has no id and a response has no method.
type rawMsg struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *RPCError        `json:"error,omitempty"`
}

// toolListResult mirrors the tools/list response.
type toolListResult struct {
	Tools []Tool `json:"tools"`
}

// InitializeResult is what a hand reports after the handshake.
type InitializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities,omitempty"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
	Instructions string `json:"instructions,omitempty"`
}
