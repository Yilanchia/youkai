package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"youkai/internal/accounts"
	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// Session resolution.
//
// The exploration graph must never hold a credential: an intent records
// `session_a: "alice"`, and the headers are attached here, immediately before the
// request, from the encrypted session store. That keeps the ledger shareable and
// the sessions in one place with one lifetime.
//
// A capability that asks for `session_a` will not run if the session is missing:
// silently proceeding with no headers would quietly turn an authorised comparison
// into an anonymous one, and the finding would be wrong.

// resolveSessions rewrites session names into headers for the capabilities that
// accept them.
func (d *Dispatcher) resolveSessions(eng ledger.Engagement, args map[string]any) (map[string]any, error) {
	if args == nil {
		return nil, nil
	}
	needsA := strings.TrimSpace(argStringOf(args, "session_a")) != ""
	needsB := strings.TrimSpace(argStringOf(args, "session_b")) != ""
	sessionNames := argStringList(args, "sessions")

	if !needsA && !needsB && len(sessionNames) == 0 {
		return args, nil
	}

	store, err := accounts.NewSessionStore(d.sessionDir())
	if err != nil {
		return nil, err
	}

	out := make(map[string]any, len(args)+2)
	for k, v := range args {
		out[k] = v
	}

	if needsA {
		headers, err := loadSessionHeaders(store, argStringOf(args, "session_a"))
		if err != nil {
			return nil, err
		}
		out["headers_a"] = headers
	}
	if needsB {
		headers, err := loadSessionHeaders(store, argStringOf(args, "session_b"))
		if err != nil {
			return nil, err
		}
		out["headers_b"] = headers
	}
	if len(sessionNames) > 0 {
		resolved := make([]map[string]any, 0, len(sessionNames))
		for _, name := range sessionNames {
			headers, err := loadSessionHeaders(store, name)
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, map[string]any{"name": name, "headers": headers})
		}
		out["sessions"] = resolved
	}
	_ = eng
	return out, nil
}

func loadSessionHeaders(store *accounts.SessionStore, name string) (map[string]string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("accounts: 空会话名")
	}
	sess, err := store.Load(name)
	if err != nil {
		return nil, fmt.Errorf("accounts: 解析会话 %q: %w", name, err)
	}
	return sess.Headers, nil
}

// BolaPairs exposes declared ownership to the engine so it can derive tier-1
// `compare` intents. Ownership comes from the manifest or from seeded facts; it is
// never guessed.
func (d *Dispatcher) BolaPairs(ctx context.Context) ([]accounts.Pair, error) {
	m, err := accounts.Loaded(d.accountsPath())
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, nil
	}
	return m.BolaPairs(), nil
}

// ---- arg helpers -----------------------------------------------------------

func argStringOf(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	s, _ := args[key].(string)
	return s
}

func argStringList(args map[string]any, key string) []string {
	if args == nil {
		return nil
	}
	switch v := args[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	case []map[string]any:
		// Already resolved: leave it alone.
		return nil
	}
	return nil
}

// ensureJSONSafe is a guard used by tests: an intent's args must be serialisable.
func ensureJSONSafe(args map[string]any) error {
	_, err := json.Marshal(args)
	return err
}

var _ = discipline.Request{}

// TargetsFor names the URLs an account capability would touch, so the API can
// check a high-authorisation record against them before approving execution.
// Without this the API would have to choose between "skip the check" and
// "approve blindly" for capabilities whose targets live in the manifest.
func (d *Dispatcher) TargetsFor(ctx context.Context, engagementID int64, capability string, args map[string]any) []string {
	switch capability {
	case "accounts_provision", "accounts_seed", "object_seed", "accounts_register":
	default:
		return nil
	}
	m, err := accounts.Loaded(d.accountsPath())
	if err != nil || m == nil {
		return nil
	}
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		for _, e := range out {
			if e == u {
				return
			}
		}
		out = append(out, u)
	}
	for _, a := range m.Accounts {
		add(a.Login.URL)
		if a.Seed != nil && strings.TrimSpace(a.Seed.Create.URL) != "" {
			base := m.Base(a)
			u := a.Seed.Create.URL
			if !strings.Contains(u, "://") && base != "" {
				u = strings.TrimRight(base, "/") + "/" + strings.TrimLeft(u, "/")
			}
			add(u)
		}
		for _, own := range a.Owns {
			base := m.Base(a)
			u := own.URL
			if !strings.Contains(u, "://") && base != "" {
				u = strings.TrimRight(base, "/") + "/" + strings.TrimLeft(u, "/")
			}
			add(u)
		}
	}
	return out
}
