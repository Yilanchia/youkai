package hands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"youkai/internal/mcp"
)

// Set is the live pair of hands. It implements loop.Hands.
type Set struct {
	mu      sync.RWMutex
	clients map[string]*mcp.Client
	tools   map[string]map[string]bool // hand -> advertised tool names
}

// Dial starts every configured hand and reads its tool inventory.
func Dial(ctx context.Context, cfg Config) (*Set, error) {
	fairyOn, verdexOn := cfg.Configured()
	if !fairyOn && !verdexOn {
		return nil, fmt.Errorf("no hands configured: %s needs a fairy and/or verdex entry", DefaultConfigPath)
	}

	s := &Set{
		clients: map[string]*mcp.Client{},
		tools:   map[string]map[string]bool{},
	}

	entries := []struct {
		name string
		hc   mcp.HandConfig
		on   bool
	}{
		{Fairy, cfg.Fairy, fairyOn},
		{Verdex, cfg.Verdex, verdexOn},
	}

	for _, e := range entries {
		if !e.on {
			continue
		}
		hc := e.hc
		hc.Name = e.name
		client, err := mcp.Dial(ctx, hc)
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("dial %s: %w", e.name, err)
		}
		// Listing tools needs its own budget: some hands load a lot of code.
		listCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		tools, err := client.ListTools(listCtx)
		cancel()
		if err != nil {
			_ = client.Close()
			_ = s.Close()
			return nil, fmt.Errorf("list tools on %s: %w", e.name, err)
		}
		set := make(map[string]bool, len(tools))
		for _, t := range tools {
			set[t.Name] = true
		}
		s.clients[e.name] = client
		s.tools[e.name] = set
	}
	return s, nil
}

// Close shuts every hand down.
func (s *Set) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	names := make([]string, 0, len(s.clients))
	for name := range s.clients {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := s.clients[name].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.clients = map[string]*mcp.Client{}
	return firstErr
}

// Hands lists the connected hand names.
func (s *Set) Hands() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.clients))
	for name := range s.clients {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ToolNames returns a hand's advertised tools, sorted.
func (s *Set) ToolNames(hand string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	set := s.tools[hand]
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ServerInfo reports what each hand said during the handshake.
func (s *Set) ServerInfo(hand string) (mcp.InitializeResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[hand]
	if !ok {
		return mcp.InitializeResult{}, false
	}
	return c.ServerInfo(), true
}

// HandFor implements loop.Hands: which hand owns this tool?
//
// Authoritative source is what the hands advertise; the prefix rule is only a
// fallback so a typo'd tool name produces a clear error instead of a mystery.
func (s *Set) HandFor(tool string) (string, error) {
	tool = Canonical(tool)
	s.mu.RLock()
	defer s.mu.RUnlock()

	var owners []string
	for name, set := range s.tools {
		if set[tool] {
			owners = append(owners, name)
		}
	}
	sort.Strings(owners)
	switch len(owners) {
	case 1:
		return owners[0], nil
	case 0:
		if owner, ok := OwnerByPrefix(tool); ok {
			if _, connected := s.clients[owner]; connected {
				return owner, nil
			}
			return "", fmt.Errorf("tool %q belongs to the %s hand, which is not connected", tool, owner)
		}
		return "", fmt.Errorf("unknown tool %q: neither hand advertises it", tool)
	default:
		// Both advertise the same name (should not happen). Prefer the hand the
		// prefix rule names, then fail loudly rather than guess.
		if owner, ok := OwnerByPrefix(tool); ok {
			for _, o := range owners {
				if o == owner {
					return owner, nil
				}
			}
		}
		return "", fmt.Errorf("tool %q is advertised by multiple hands: %s", tool, strings.Join(owners, ", "))
	}
}

// Call implements loop.Hands.
func (s *Set) Call(ctx context.Context, hand, tool string, args map[string]any) (mcp.ToolResult, error) {
	tool = Canonical(tool)
	s.mu.RLock()
	client, ok := s.clients[hand]
	advertised := s.tools[hand][tool]
	s.mu.RUnlock()

	if !ok {
		return mcp.ToolResult{}, fmt.Errorf("hand %q is not connected", hand)
	}
	if !advertised {
		return mcp.ToolResult{}, fmt.Errorf("hand %q does not advertise tool %q", hand, tool)
	}
	return client.CallTool(ctx, tool, args)
}
