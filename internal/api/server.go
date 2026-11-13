// Package api is youkai's control plane: HTTP + SSE on loopback, a local token,
// and an Origin check.
//
// The UI is a control surface, not an autonomy switch. There is no endpoint that
// batch-approves, no endpoint that runs an exploitation step, and the only
// tier-2 execution route is one intent at a time with two independent human
// conditions (an operator approval AND a valid high-authorisation record).
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"youkai/internal/discipline"
	"youkai/internal/engine"
	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// Config configures the server.
type Config struct {
	// Addr must be loopback. The server refuses anything else.
	Addr string
	// Token is the local API token. Generated when empty.
	Token string
	// Store is the ledger.
	Store *ledger.Store
	// Dispatcher runs capabilities (built by the runtime package).
	Dispatcher engine.Dispatcher
	// ArtifactDir is where binary artifacts are isolated.
	ArtifactDir string
	// HighAuthKey is the FAIRY_AUTH_KEY used to *verify* high-auth records.
	// Empty means tier-2 execution is disabled (approval still works).
	HighAuthKey string
	// LLM describes the optional planner for the config panel (never the key).
	LLM LLMInfo
	// Proposer is the optional LLM planner (proposal only).
	Proposer engine.Proposer
	// MaxSteps defaults to 10 for UI-triggered runs.
	MaxSteps int
	// Logger defaults to the standard logger.
	Logger *log.Logger
}

// LLMInfo is what the UI may show about the planner: no secrets.
type LLMInfo struct {
	Enabled    bool   `json:"enabled"`
	BaseURL    string `json:"base_url,omitempty"`
	Model      string `json:"model,omitempty"`
	KeyFromEnv string `json:"key_from_env,omitempty"`
	KeyPresent bool   `json:"key_present"`
}

// Server is the HTTP control plane.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	logger  *log.Logger
	hub     *broadcaster
	mu      sync.Mutex
	running map[int64]int64 // engagement id -> current run id
	runMu   sync.Map        // runID -> *runState
	started time.Time
}

type runState struct {
	mu   sync.Mutex
	done bool
	rep  engine.Report
	err  string
}

// New builds the server.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("api: store is required")
	}
	if cfg.Dispatcher == nil {
		return nil, errors.New("api: dispatcher is required")
	}
	if cfg.MaxSteps <= 0 {
		cfg.MaxSteps = engine.DefaultMaxSteps
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("api: addr %q: %w", cfg.Addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("api: refusing to listen on %q: youkai is loopback-only", cfg.Addr)
	}
	if cfg.Token == "" {
		cfg.Token = NewToken()
	}
	s := &Server{
		cfg:     cfg,
		mux:     http.NewServeMux(),
		logger:  cfg.Logger,
		hub:     newBroadcaster(),
		running: map[int64]int64{},
		started: time.Now(),
	}
	s.routes()
	return s, nil
}

// NewToken mints a local API token.
func NewToken() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("youkai-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// Token is the token clients must send.
func (s *Server) Token() string { return s.cfg.Token }

// Handler returns the root handler (auth + origin applied).
func (s *Server) Handler() http.Handler {
	return s.withOrigin(s.withAuth(s.mux))
}

// ListenAndServe blocks serving until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	s.logger.Printf("youkai: control plane on http://%s (token required)", s.cfg.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ---- middleware ------------------------------------------------------------

// withOrigin rejects cross-origin browser requests. Even on loopback, a malicious
// web page must not be able to drive the API with a stolen/guessed token pair.
func (s *Server) withOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !s.originAllowed(origin) {
			writeErr(w, http.StatusForbidden, "origin %q is not allowed", origin)
			return
		}
		// Defence in depth: no CORS approval is ever granted.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin string) bool {
	_, port, _ := net.SplitHostPort(s.cfg.Addr)
	for _, allowed := range []string{
		"http://127.0.0.1:" + port, "http://localhost:" + port, "http://[::1]:" + port,
	} {
		if origin == allowed {
			return true
		}
	}
	return false
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The SPA shell and its assets are public: they contain no data.
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/assets/") {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		got := r.Header.Get("X-Youkai-Token")
		if got == "" {
			got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if got == "" {
			got = r.URL.Query().Get("token") // SSE/EventSource cannot set headers
		}
		if !constEq(got, s.cfg.Token) {
			writeErr(w, http.StatusUnauthorized, "missing or invalid token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func constEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ---- routes ----------------------------------------------------------------

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("/api/health", s.handleHealth)
	m.HandleFunc("/api/config", s.handleConfig)
	m.HandleFunc("/api/engagements", s.handleEngagements)
	m.HandleFunc("/api/engagements/", s.handleEngagementScoped)

	// SPA
	m.Handle("/", s.spaHandler())
	m.Handle("/assets/", s.assetsHandler())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"version":     Version,
		"uptime_s":    int(time.Since(s.started).Seconds()),
		"provider":    gate.Provider().Reason(),
		"highauth":    s.cfg.HighAuthKey != "",
		"planner":     s.cfg.LLM.Enabled,
		"artifactdir": s.cfg.ArtifactDir,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": Version,
		"llm":     s.cfg.LLM,
		"provider": map[string]any{
			"available": gate.Provider().Available(),
			"reason":    gate.Provider().Reason(),
		},
		"highauth": map[string]any{"configured": s.cfg.HighAuthKey != "", "env": discipline.HighAuthKeyEnv},
		"tiers": map[string]any{
			"read_only": gate.ReadOnlyCapabilities(),
			"proof":     gate.ProofCapabilities(),
		},
		"artifacts": s.cfg.ArtifactDir,
	})
}

func (s *Server) handleEngagements(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.cfg.Store.ListEngagements(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, list)
	case http.MethodPost:
		var body struct {
			Name  string          `json:"name"`
			Scope json.RawMessage `json:"scope"`
		}
		if err := decodeJSON(w, r, &body); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		if strings.TrimSpace(body.Name) == "" {
			writeErr(w, http.StatusBadRequest, "name is required")
			return
		}
		// Validate the scope by loading it as a passport; an unusable passport
		// must not reach the database.
		var sc discipline.Scope
		if len(body.Scope) > 0 {
			if err := json.Unmarshal(body.Scope, &sc); err != nil {
				writeErr(w, http.StatusBadRequest, "scope: %v", err)
				return
			}
			if err := sc.Validate(); err != nil {
				writeErr(w, http.StatusBadRequest, "scope: %v", err)
				return
			}
		}
		e, err := s.cfg.Store.CreateEngagement(r.Context(), body.Name, sc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		s.hub.publish("engagements", map[string]any{"type": "engagement", "id": e.ID, "name": e.Name})
		writeJSON(w, http.StatusCreated, e)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET or POST")
	}
}

// handleEngagementScoped dispatches /api/engagements/{id}/...
func (s *Server) handleEngagementScoped(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/engagements/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, http.StatusNotFound, "missing engagement id")
		return
	}
	id, err := parseID(parts[0])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad engagement id")
		return
	}
	eng, err := s.engagementByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "engagement %d: %v", id, err)
		return
	}
	tail := parts[1:]

	switch {
	case len(tail) == 0 && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, eng)
	case len(tail) == 0:
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
	case len(tail) >= 1 && tail[0] == "graph" && r.Method == http.MethodGet:
		g, err := s.cfg.Store.Graph(r.Context(), id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, g)
	case len(tail) >= 1 && tail[0] == "events":
		s.handleEvents(w, r, eng)
	case len(tail) >= 1 && tail[0] == "runs":
		s.handleRuns(w, r, eng, tail[1:])
	case len(tail) >= 1 && tail[0] == "intents":
		s.handleIntents(w, r, eng, tail[1:])
	case len(tail) >= 1 && tail[0] == "findings":
		s.handleFindings(w, r, eng, tail[1:])
	case len(tail) >= 1 && tail[0] == "report":
		s.handleReport(w, r, eng)
	case len(tail) >= 1 && tail[0] == "audit":
		rows, err := s.cfg.Store.AuditTail(r.Context(), eng.Name, queryInt(r, "limit", 200))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	default:
		writeErr(w, http.StatusNotFound, "no route %s", r.URL.Path)
	}
}

func (s *Server) engagementByID(ctx context.Context, id int64) (ledger.Engagement, error) {
	list, err := s.cfg.Store.ListEngagements(ctx)
	if err != nil {
		return ledger.Engagement{}, err
	}
	for _, e := range list {
		if e.ID == id {
			return e, nil
		}
	}
	return ledger.Engagement{}, ledger.ErrNotFound
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request, eng ledger.Engagement, tail []string) {
	if len(tail) == 0 {
		switch r.Method {
		case http.MethodGet:
			runs, err := s.cfg.Store.ListRuns(r.Context(), eng.ID, queryInt(r, "limit", 50))
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "%v", err)
				return
			}
			writeJSON(w, http.StatusOK, runs)
		case http.MethodPost:
			s.startRun(w, r, eng)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "GET or POST")
		}
		return
	}
	runID, err := parseID(tail[0])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad run id")
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	run, err := s.cfg.Store.GetRun(r.Context(), eng.ID, runID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "%v", err)
		return
	}
	payload := map[string]any{"run": run}
	if v, ok := s.runMu.Load(runID); ok {
		rs := v.(*runState)
		rs.mu.Lock()
		payload["report"] = rs.rep
		payload["done"] = rs.done
		if rs.err != "" {
			payload["error"] = rs.err
		}
		rs.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) startRun(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	var body struct {
		SeedURLs []string `json:"seed_urls"`
		MaxSteps int      `json:"max_steps"`
	}
	_ = decodeJSON(w, r, &body)

	s.mu.Lock()
	if existing, busy := s.running[eng.ID]; busy {
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, "engagement %d already has run %d in flight", eng.ID, existing)
		return
	}
	run, err := s.cfg.Store.CreateRun(r.Context(), eng.ID, map[string]any{
		"seed_urls": body.SeedURLs, "max_steps": body.MaxSteps, "trigger": "api",
	})
	if err != nil {
		s.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	s.running[eng.ID] = run.ID
	s.mu.Unlock()

	st := &runState{}
	s.runMu.Store(run.ID, st)

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.running, eng.ID)
			s.mu.Unlock()
			s.hub.publish("runs", map[string]any{"type": "run_finished", "run_id": run.ID, "engagement": eng.Name})
		}()

		maxSteps := body.MaxSteps
		if maxSteps <= 0 {
			maxSteps = s.cfg.MaxSteps
		}
		eng2, nerr := engine.New(engine.Config{
			Store:        s.cfg.Store,
			EngagementID: eng.ID,
			Engagement:   eng.Name,
			Dispatcher:   s.cfg.Dispatcher,
			MaxSteps:     maxSteps,
			SeedURLs:     body.SeedURLs,
			AllowedTools: gate.ReadOnlyCapabilities(),
			Proposer:     s.cfg.Proposer,
		})
		if nerr != nil {
			st.mu.Lock()
			st.done = true
			st.err = nerr.Error()
			st.mu.Unlock()
			_ = s.cfg.Store.FinishRun(context.Background(), run.ID, engine.StopError, nerr.Error(), 0, 0)
			return
		}
		rep, err := eng2.Run(context.Background(), run.ID)
		st.mu.Lock()
		st.done = true
		st.rep = rep
		if err != nil {
			st.err = err.Error()
		}
		st.mu.Unlock()
		status := rep.Stop
		if err != nil {
			status = engine.StopError
		}
		_ = s.cfg.Store.FinishRun(context.Background(), run.ID, status, rep.Reason, len(rep.Steps), rep.Derived)
		s.logger.Printf("youkai: run %d finished: %s (%d steps)", run.ID, status, len(rep.Steps))
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{"run_id": run.ID, "status": "running"})
}

// ---- SSE -------------------------------------------------------------------

// handleEvents streams a snapshot every second. Polling under an SSE envelope
// keeps the server stateless per connection: no lost-event bookkeeping, and a
// reconnecting browser always gets the current truth.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	send := func() bool {
		g, err := s.cfg.Store.Graph(r.Context(), eng.ID)
		if err != nil {
			return false
		}
		payload := map[string]any{"graph": g}
		if runID, busy := s.currentRun(eng.ID); busy {
			payload["running_run_id"] = runID
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !send() {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !send() {
				return
			}
		}
	}
}

func (s *Server) currentRun(engagementID int64) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.running[engagementID]
	return id, ok
}

// ---- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, format string, args ...any) {
	writeJSON(w, code, map[string]any{"error": fmt.Sprintf(format, args...)})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func parseID(s string) (int64, error) {
	var id int64
	_, err := fmt.Sscanf(s, "%d", &id)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("bad id %q", s)
	}
	return id, nil
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}

// broadcaster is a tiny in-process pub/sub for run lifecycle events.
type broadcaster struct {
	mu   sync.Mutex
	subs map[string][]chan map[string]any
}

func newBroadcaster() *broadcaster {
	return &broadcaster{subs: map[string][]chan map[string]any{}}
}

func (b *broadcaster) subscribe(topic string) chan map[string]any {
	ch := make(chan map[string]any, 8)
	b.mu.Lock()
	b.subs[topic] = append(b.subs[topic], ch)
	b.mu.Unlock()
	return ch
}

func (b *broadcaster) publish(topic string, ev map[string]any) {
	b.mu.Lock()
	subs := append([]chan map[string]any(nil), b.subs[topic]...)
	b.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Version is the platform version.
const Version = "0.2.0"
