// Package runtime wires the capability packages to the engine without letting
// the engine import them.
//
// It also owns the per-engagement Guard cache. That is the piece that makes the
// discipline spine real after the monolith decision: a capability is never given
// an HTTP client, only a Guard built from that engagement's passport. No passport,
// no capability.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"youkai/internal/binary"
	"youkai/internal/discipline"
	"youkai/internal/ledger"
	"youkai/internal/web"
)

// Dispatcher routes a capability to the package that owns it, with a Guard built
// from the engagement's current passport.
type Dispatcher struct {
	Store *ledger.Store
	// ArtifactBase is the root for isolated samples, one subdirectory per engagement.
	ArtifactBase string

	mu     sync.Mutex
	caches map[int64]*guardEntry
}

type guardEntry struct {
	scopeRaw string
	guard    *discipline.Guard
}

// New builds a dispatcher.
func New(store *ledger.Store, artifactBase string) *Dispatcher {
	return &Dispatcher{Store: store, ArtifactBase: artifactBase, caches: map[int64]*guardEntry{}}
}

// Run implements engine.Dispatcher.
func (d *Dispatcher) Run(ctx context.Context, engagementID int64, capability string, args map[string]any) (ledger.Observation, error) {
	eng, scope, err := d.engagement(ctx, engagementID)
	if err != nil {
		return ledger.Observation{}, err
	}

	if c, ok := web.Lookup(capability); ok {
		guard, err := d.guardFor(ctx, eng, scope)
		if err != nil {
			return ledger.Observation{}, err
		}
		return c.Run(ctx, &web.Env{
			Guard:        guard,
			Store:        d.Store,
			EngagementID: eng.ID,
			Engagement:   eng.Name,
		}, args)
	}
	if c, ok := binary.Lookup(capability); ok {
		dir := filepath.Join(d.ArtifactBase, sanitiseName(eng.Name))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return ledger.Observation{}, fmt.Errorf("runtime: artifact dir: %w", err)
		}
		return c.Run(ctx, &binary.Env{
			ArtifactDir:  dir,
			EngagementID: eng.ID,
			Engagement:   eng.Name,
		}, args)
	}
	return ledger.Observation{}, fmt.Errorf("runtime: no capability named %q", capability)
}

// Has reports whether a capability is registered at all.
func (d *Dispatcher) Has(capability string) bool {
	if _, ok := web.Lookup(capability); ok {
		return true
	}
	_, ok := binary.Lookup(capability)
	return ok
}

// Names lists every registered capability with its package.
func (d *Dispatcher) Names() map[string][]string {
	out := map[string][]string{}
	for _, c := range web.Registry() {
		out["web"] = append(out["web"], c.Name)
	}
	for _, c := range binary.Registry() {
		out["binary"] = append(out["binary"], c.Name)
	}
	return out
}

// engagement loads the engagement and parses its passport.
func (d *Dispatcher) engagement(ctx context.Context, id int64) (ledger.Engagement, *discipline.Scope, error) {
	list, err := d.Store.ListEngagements(ctx)
	if err != nil {
		return ledger.Engagement{}, nil, err
	}
	for _, e := range list {
		if e.ID != id {
			continue
		}
		if len(e.Scope) == 0 || string(e.Scope) == "{}" {
			return e, nil, fmt.Errorf("runtime: engagement %q has no scope passport; nothing may be requested", e.Name)
		}
		var sc discipline.Scope
		if err := json.Unmarshal(e.Scope, &sc); err != nil {
			return e, nil, fmt.Errorf("runtime: engagement %q scope: %w", e.Name, err)
		}
		normalised := discipline.NewScope(sc)
		if err := normalised.Validate(); err != nil {
			return e, nil, fmt.Errorf("runtime: engagement %q scope: %w", e.Name, err)
		}
		return e, normalised, nil
	}
	return ledger.Engagement{}, nil, ledger.ErrNotFound
}

// guardFor returns the engagement's guard, rebuilding it when the passport changed.
func (d *Dispatcher) guardFor(ctx context.Context, eng ledger.Engagement, scope *discipline.Scope) (*discipline.Guard, error) {
	raw := string(eng.Scope)
	d.mu.Lock()
	entry, ok := d.caches[eng.ID]
	d.mu.Unlock()
	if ok && entry.scopeRaw == raw {
		return entry.guard, nil
	}
	g, err := discipline.NewGuard(scope, eng.Name, d.Store)
	if err != nil {
		return nil, fmt.Errorf("runtime: build guard for %q: %w", eng.Name, err)
	}
	d.mu.Lock()
	d.caches[eng.ID] = &guardEntry{scopeRaw: raw, guard: g}
	d.mu.Unlock()
	return g, nil
}

// sanitiseName keeps an engagement name usable as a directory name.
func sanitiseName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		out = "engagement"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}
