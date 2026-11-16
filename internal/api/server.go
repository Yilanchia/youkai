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
	"strconv"
	"strings"
	"sync"
	"time"

	"youkai/internal/accounts"
	"youkai/internal/config"
	"youkai/internal/discipline"
	"youkai/internal/engine"
	"youkai/internal/gate"
	"youkai/internal/ledger"
	"youkai/internal/planner"
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
	HighAuthKey string
	// RequireHighAuth restores the ADR-005 rule: a tier-2 step against a network
	// target needs a signed record on top of the approval row. Off by default -
	// ADR-006 explains why one clear click beats a cryptographic ritual nobody
	// performs correctly on a loopback console.
	RequireHighAuth bool
	// Settings persists runtime configuration (LLM API). Optional: without it the
	// LLM panel is read-only and environment-only.
	Settings *config.Store
	// Planner is the hot-swappable LLM planner.
	Planner *planner.Manager
	// Proposer is the optional LLM planner (proposal only).
	Proposer engine.Proposer
	// PairSource supplies declared ownership (the account layer) so the engine can
	// derive tier-1 BOLA comparisons.
	PairSource engine.PairSource
	// MaxSteps defaults to 10 for UI-triggered runs.
	MaxSteps int
	// SuperviseBudget is the total step budget of one supervised session (all
	// rounds together). Zero means defaultSuperviseBudget. Crossing it is a TRUE
	// stop: the operator decides whether to spend another session.
	SuperviseBudget int
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
	// llmProblem is why the configured model did not load (a key that no longer
	// decrypts, a rejected config). Empty means "nothing to report".
	llmMu      sync.Mutex
	llmProblem string
}

type runState struct {
	mu     sync.Mutex
	done   bool
	rep    engine.Report
	err    string
	cancel context.CancelFunc
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
	m.HandleFunc("/api/config/llm", s.handleLLMConfig)
	m.HandleFunc("/api/config/llm/test", s.handleLLMTest)
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
		"planner":     s.proposer() != nil,
		"artifactdir": s.cfg.ArtifactDir,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	llm, _ := s.llmView(r.Context())
	payload := map[string]any{
		"version": Version,
		"llm":     llm,
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
	}
	// The aggregate view carries the same explanation as /api/config/llm, so the UI
	// can show it on first paint without a second request.
	if problem := s.LLMProblem(); problem != "" {
		payload["problem"] = problem
	}
	writeJSON(w, http.StatusOK, payload)
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
		// must not reach the database. NewScope fills the safe defaults (read-only
		// method set, rate limit, budget, body cap) so a partial form from the UI
		// cannot accidentally produce an unrestricted passport.
		var sc discipline.Scope
		if len(body.Scope) > 0 {
			if err := json.Unmarshal(body.Scope, &sc); err != nil {
				writeErr(w, http.StatusBadRequest, "%v", err)
				return
			}
			sc = *discipline.NewScope(sc)
			if err := sc.Validate(); err != nil {
				writeErr(w, http.StatusBadRequest, "%v", err)
				return
			}
		}
		e, err := s.cfg.Store.CreateEngagement(r.Context(), body.Name, sc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		if warns := scopeWarnings(sc); len(warns) > 0 {
			writeJSON(w, http.StatusCreated, map[string]any{"engagement": e, "warnings": warns})
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
	case len(tail) >= 1 && tail[0] == "run-steps":
		// The same stream the SSE endpoint sends, readable on demand: a refresh
		// rebuilds the transcript instead of starting from an empty panel.
		since := 0
		if v := r.URL.Query().Get("since"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				since = n
			}
		}
		steps, err := s.cfg.Store.RunStepsSince(r.Context(), id, since, 200)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, steps)
	case len(tail) >= 1 && tail[0] == "runs":
		s.handleRuns(w, r, eng, tail[1:])
	case len(tail) >= 1 && tail[0] == "intents":
		s.handleIntents(w, r, eng, tail[1:])
	case len(tail) >= 1 && tail[0] == "findings":
		s.handleFindings(w, r, eng, tail[1:])
	case len(tail) >= 1 && tail[0] == "report":
		s.handleReport(w, r, eng)
	case len(tail) >= 1 && tail[0] == "reports":
		s.handleSnapshots(w, r, eng, tail[1:])
	case len(tail) >= 1 && tail[0] == "sarif":
		s.handleSARIF(w, r, eng)
	case len(tail) >= 1 && tail[0] == "disclosure":
		s.handleDisclosure(w, r, eng)
	case len(tail) >= 1 && tail[0] == "scope":
		s.handleScope(w, r, eng)
	case len(tail) >= 1 && tail[0] == "accounts":
		s.handleAccounts(w, r, eng)
	case len(tail) >= 1 && tail[0] == "hypotheses":
		rows, err := s.cfg.Store.ListHypotheses(r.Context(), eng.ID, r.URL.Query().Get("state"))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	case len(tail) >= 1 && tail[0] == "mandate":
		s.handleMandate(w, r, eng, tail[1:])
	case len(tail) >= 1 && tail[0] == "chat":
		s.handleChat(w, r, eng)
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
	if len(tail) >= 2 && tail[1] == "cancel" {
		// "停下" must be instant: it cancels the supervised loop, not just the round
		// in flight, so the operator can always take the wheel back.
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		s.cancelRun(w, eng, runID)
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

	// No passport, no action. Without this the run starts, derives steps that the
	// guard then refuses one by one, and reports an idle run instead of telling the
	// operator what is actually missing (found by the v0.5 E2E walkthrough).
	var passport discipline.Scope
	if len(eng.Scope) > 0 {
		_ = json.Unmarshal(eng.Scope, &passport)
	}
	if len(passport.Include) == 0 {
		writeErr(w, http.StatusBadRequest, "这个作业还没有护照(include 为空):youkai 不会在没有授权目标时动作,先填 scope")
		return
	}
	if err := passport.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "护照不可用:%v", err)
		return
	}

	s.mu.Lock()
	if existing, busy := s.running[eng.ID]; busy {
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, "engagement %d already has run %d in flight", eng.ID, existing)
		return
	}
	// A caller that only says "go" (the conversation's confirm button) gets the
	// passport's own surfaces as seeds. Without this the run bootstraps from an
	// empty list and reports idle - the "started but did nothing" symptom.
	seeds := body.SeedURLs
	if len(seeds) == 0 {
		seeds = passportSurfaces(passport)
	}
	run, err := s.cfg.Store.CreateRun(r.Context(), eng.ID, map[string]any{
		"seed_urls": seeds, "max_steps": body.MaxSteps, "trigger": "api",
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

		perRound := body.MaxSteps
		if perRound <= 0 {
			perRound = s.cfg.MaxSteps
		}
		// Every step the engine finishes is narrated to the operator and stored, so a
		// run is watchable while it happens and readable afterwards. The hook only
		// receives the sanitised StepEvent; it never sees a response body.
		onStep := func(ev engine.StepEvent) {
			ev.RunID = run.ID
			s.narrate(eng.ID, ev)
		}

		// Supervision: a run that stops only because it hit its per-round step cap is
		// a FALSE stop - there is still read-only work to do, and making the operator
		// click "continue" every ten steps is what makes an agent feel dead.
		//
		// A TRUE stop (needs_approval / sensitive / idle / error / cancel) is never
		// crossed. That is the whole boundary of this feature.
		budget := s.cfg.SuperviseBudget
		if budget <= 0 {
			budget = defaultSuperviseBudget
		}
		if budget < perRound {
			budget = perRound
		}
		ctx, cancel := context.WithCancel(context.Background())
		st.mu.Lock()
		st.cancel = cancel
		st.mu.Unlock()
		defer cancel()

		total := 0
		rep := engine.Report{Stop: engine.StopError, Reason: "no round ran"}
		status := engine.StopError
		for round := 1; ; round++ {
			left := budget - total
			if left <= 0 {
				status = engine.StopMaxSteps
				rep.Reason = fmt.Sprintf("已达本次托管预算(%d 步),点「继续托管」可再跑一程", budget)
				break
			}
			thisRound := perRound
			if left < thisRound {
				thisRound = left
			}
			eng2, nerr := engine.New(engine.Config{
				Store:           s.cfg.Store,
				EngagementID:    eng.ID,
				Engagement:      eng.Name,
				Dispatcher:      s.cfg.Dispatcher,
				MaxSteps:        thisRound,
				SeedURLs:        seeds,
				AllowedTools:    gate.ReadOnlyCapabilities(),
				Proposer:        s.proposer(),
				PairSource:      s.cfg.PairSource,
				RequireHighAuth: s.cfg.RequireHighAuth,
				NoFinishRun:     true,
				OnStep:          onStep,
			})
			if nerr != nil {
				st.mu.Lock()
				st.done = true
				st.err = nerr.Error()
				st.mu.Unlock()
				_ = s.cfg.Store.FinishRun(context.Background(), run.ID, engine.StopError, nerr.Error(), total, rep.Derived)
				return
			}
			roundRep, err := eng2.Run(ctx, run.ID)
			total += len(roundRep.Steps)
			rep = roundRep
			rep.Derived += 0
			if err != nil {
				status = engine.StopError
				rep.Reason = err.Error()
				break
			}
			status = roundRep.Stop
			s.logger.Printf("youkai: supervise round %d: stop=%s steps=%d total=%d/%d",
				round, status, len(roundRep.Steps), total, budget)
			if status != engine.StopMaxSteps || ctx.Err() != nil {
				break
			}

			// A false stop: say so in the stream, then keep going.
			s.narrate(eng.ID, engine.StepEvent{
				RunID: run.ID, Phase: engine.PhaseDerive, Status: "info",
				Summary: fmt.Sprintf("继续托管:这一轮到了单轮上限,只读工作还没做完(已 %d 步,预算 %d)", total, budget),
			})
		}

		st.mu.Lock()
		st.done = true
		st.rep = rep
		if status == engine.StopError && rep.Reason != "" {
			st.err = rep.Reason
		}
		st.mu.Unlock()
		rep.Stop = status
		// A run that took steps and had every request refused by the passport must
		// say so, instead of reporting whatever the last optional step complained
		// about: "nothing was allowed" is the fact the operator needs.
		if reason, overridden := s.blockedRunReason(context.Background(), eng.Name, rep); overridden {
			rep.Reason = reason
		}
		// A real stop is the end of a turn, so the agent says something: what it
		// found, why it stopped, what the operator can do next. Deterministic text,
		// no model required - a harness that goes silent at the end is worse than
		// one that never spoke.
		//
		// Written BEFORE FinishRun: a reader that sees the run finished must be able
		// to find the closing words already in the conversation (otherwise the UI
		// races and shows a turn that ends in silence).
		s.summariseStop(context.Background(), eng, status, rep.Reason, total)
		_ = s.cfg.Store.FinishRun(context.Background(), run.ID, status, rep.Reason, total, rep.Derived)
		// The stop event is emitted by the engine's own finish(), once per round; a
		// second one here would show the same line twice in the timeline.
		s.logger.Printf("youkai: run %d finished: %s (%d steps, budget %d)", run.ID, status, total, budget)
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

	// Step stream. The client tells us the last seq it saw; everything after that is
	// replayed from the database, so a refresh or a dropped connection resumes
	// exactly where it left off instead of losing the middle of a run.
	since := 0
	if v := r.URL.Query().Get("since"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			since = n
		}
	}
	sendSteps := func() bool {
		steps, err := s.cfg.Store.RunStepsSince(r.Context(), eng.ID, since, 200)
		if err != nil || len(steps) == 0 {
			return err == nil
		}
		for _, st := range steps {
			b, merr := json.Marshal(st)
			if merr != nil {
				return false
			}
			if _, werr := fmt.Fprintf(w, "event: step\ndata: %s\n\n", b); werr != nil {
				return false
			}
			since = st.Seq
		}
		flusher.Flush()
		return true
	}

	// While a run is in flight the stream is ticked faster: the whole point is that
	// the operator watches the steps appear, not that they appear a second late.
	fast, slow := 300*time.Millisecond, time.Second
	ticker := time.NewTicker(slow)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !send() || !sendSteps() {
				return
			}
			want := slow
			if _, busy := s.currentRun(eng.ID); busy {
				want = fast
			}
			ticker.Reset(want)
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

// AccountsViewer is implemented by a dispatcher that can render the identity view.
// It is a narrow optional interface so the API does not depend on the runtime
// package (and tests can omit it).
type AccountsViewer interface {
	AccountsView(ctx context.Context, engagementID int64) (accounts.Show, error)
}

// handleAccounts serves the redacted identity view.
//
// Read-only on purpose: provisioning, seeding and registration are tier-2
// capabilities that reach the target through the approval workbench, not through
// a convenience endpoint here.
func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	viewer, ok := s.cfg.Dispatcher.(AccountsViewer)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"accounts": []any{}, "bola_pairs": []any{},
			"warnings": []string{"this build has no account layer wired"},
		})
		return
	}
	view, err := viewer.AccountsView(r.Context(), eng.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// proposer returns the LLM proposer to install in a run, or nil when disabled.
//
// The engine treats a nil proposer as "no LLM": the deterministic loop is the
// baseline, and the model is an optional supplement. A mid-run disable therefore
// degrades to "no extra proposals", never to a crash.
func (s *Server) proposer() engine.Proposer {
	if s.cfg.Planner == nil || !s.cfg.Planner.Enabled() {
		return nil
	}
	return s.cfg.Planner
}

// LoadLLM resolves the startup LLM configuration: settings > environment > disabled.
func (s *Server) LoadLLM(ctx context.Context) error { return s.installLLMFromStore(ctx) }

// blockedRunReason explains a run whose requests the passport refused.
//
// Without it the operator sees the deterministic loop "finish" with a planner
// message and has to dig into the audit log to learn that every request was
// blocked (typically allow_private missing on a lab target). The guard is right to
// refuse; the report should not hide it.
func (s *Server) blockedRunReason(ctx context.Context, engagement string, rep engine.Report) (string, bool) {
	if len(rep.Steps) == 0 {
		return "", false
	}
	rows, err := s.cfg.Store.AuditTail(ctx, engagement, 1000)
	if err != nil {
		return "", false
	}
	allowed, blocked := 0, 0
	reasons := map[string]int{}
	for _, r := range rows {
		switch r.Verdict {
		case discipline.VerdictAllowed:
			allowed++
		case discipline.VerdictBlocked:
			blocked++
			reasons[r.Reason]++
		}
	}
	if allowed > 0 || blocked == 0 {
		return "", false
	}
	top := ""
	best := 0
	for reason, n := range reasons {
		if n > best {
			best, top = n, reason
		}
	}
	return fmt.Sprintf("所有请求都被护照拦断(%d 次);原因:%s。若是自建靶场,检查 scope 的 allow_private 与 include。",
		blocked, top), true
}

// scopeWarnings flags passports that will refuse their own targets at request
// time. The guard is right to refuse; telling the operator up front saves a run
// that does nothing but fill the audit log with blocks.
func scopeWarnings(sc discipline.Scope) []string {
	if sc.AllowPrivate {
		return nil
	}
	var out []string
	for _, host := range sc.Include {
		h := host
		if i := strings.IndexByte(h, ':'); i > 0 && !strings.Contains(h, "://") {
			h = h[:i]
		}
		if h == "127.0.0.1" || h == "localhost" || h == "::1" {
			out = append(out, fmt.Sprintf(
				"include 里的 %s 是环回地址,但没开 allow_private:所有请求都会被 guard 拦断", host))
			break
		}
	}
	return out
}

// passportSurfaces extracts concrete URLs from a passport's include list.
//
// A bare host gets a scheme (http for loopback, https otherwise), which is the same
// guess the engine's own base-URL logic makes.
func passportSurfaces(sc discipline.Scope) []string {
	var out []string
	for _, inc := range sc.Include {
		inc = strings.TrimSpace(inc)
		if inc == "" || strings.Contains(inc, "*") {
			continue
		}
		if !strings.Contains(inc, "://") {
			host := inc
			if i := strings.IndexAny(host, "/?#"); i >= 0 {
				host = host[:i]
			}
			scheme := "https"
			if strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "10.") ||
				strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "localhost") {
				scheme = "http"
			}
			inc = scheme + "://" + host
		}
		out = append(out, inc)
	}
	return out
}

// publishStep fans one narrated step out to the live listeners.
//
// The broadcaster drops for a subscriber whose buffer is full: a slow browser must
// never slow the run down. The persisted copy is the durable one.
func (s *Server) publishStep(engagementID int64, ev engine.StepEvent) {
	s.hub.publish(fmt.Sprintf("steps:%d", engagementID), map[string]any{"type": "step", "step": ev})
	s.hub.publish("runs", map[string]any{"type": "step", "engagement_id": engagementID, "step": ev})
}

// narrate stores one step and then tells the live listeners about it.
//
// Storing first is what keeps the live stream and the transcript identical: the
// sequence number the browser sees is the one the database assigned, so a refresh
// resumes exactly where the stream left off.
func (s *Server) narrate(engagementID int64, ev engine.StepEvent) {
	step := ledger.RunStep{
		RunID: ev.RunID, Phase: ev.Phase, IntentID: ev.IntentID,
		Capability: ev.Capability, Tier: ev.Tier, Target: ev.Target,
		Status: ev.Status, Summary: ev.Summary, Facts: ev.Facts,
		Findings: ev.Findings, RequestID: ev.RequestID, Reason: ev.Reason,
		Stop: ev.Stop, Tags: ev.Tags, At: ev.At,
	}
	stored, err := s.cfg.Store.AppendRunSteps(context.Background(), engagementID, []ledger.RunStep{step})
	if err != nil || len(stored) == 0 {
		return
	}
	out := stored[0]
	ev.Seq = out.Seq
	s.publishStep(engagementID, ev)
}

// defaultSuperviseBudget bounds one supervised session (all rounds together).
// It exists so "it keeps going by itself" never turns into "it runs forever".
const defaultSuperviseBudget = 50

// cancelRun stops the supervised loop for a run that is still in flight.
func (s *Server) cancelRun(w http.ResponseWriter, eng ledger.Engagement, runID int64) {
	v, ok := s.runMu.Load(runID)
	if !ok {
		writeErr(w, http.StatusNotFound, "run %d is not in flight", runID)
		return
	}
	st, _ := v.(*runState)
	st.mu.Lock()
	cancel := st.cancel
	st.mu.Unlock()
	if cancel == nil {
		writeErr(w, http.StatusConflict, "run %d has no cancellable session", runID)
		return
	}
	cancel()
	writeJSON(w, http.StatusOK, map[string]any{"run_id": runID, "cancelled": true})
}

// clipForEvent bounds a reason string the same way the engine does.
func clipForEvent(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// summariseStop writes the closing turn into the conversation.
//
// It is a template, deliberately: the same words whether or not a model is
// configured, and it never proposes to do something by itself - it names the
// choices and waits.
func (s *Server) summariseStop(ctx context.Context, eng ledger.Engagement, status, reason string, steps int) {
	if s.cfg.Store == nil {
		return
	}
	g, err := s.cfg.Store.Graph(ctx, eng.ID)
	if err != nil {
		return
	}
	st := g.Stats
	var text string
	switch status {
	case engine.StopNeedsApproval:
		text = fmt.Sprintf("我先停在这里:有动作需要你拍板(见上面的步骤流)。"+
			"到目前为止 %d 次请求、%d 条候选发现。批了我接着跑,不批就跳过它。",
			st.AuditAllowed, st.Findings)
	case engine.StopMaxSteps:
		text = fmt.Sprintf("这一程的托管预算用完了(%d 步)。目前 %d 次请求、%d 条候选发现。"+
			"还想继续就再点一次「开始扫描」,或者先看结果。", steps, st.AuditAllowed, st.Findings)
	case engine.StopCancelled:
		text = fmt.Sprintf("按你的要求停下了。目前 %d 次请求、%d 条候选发现,已经跑过的步骤都在上面。",
			st.AuditAllowed, st.Findings)
	case engine.StopSensitive:
		text = "我停在这里:遇到了疑似敏感数据。这类东西我不会继续读,也不会写进报告正文 —— 请你人工确认。"
	case engine.StopIdle:
		text = fmt.Sprintf("这一程只读检查跑完了:%d 次请求、%d 条候选发现(已确认 0 —— candidate 不等于 verified)。"+
			"接下来可以:看结果、让我继续深挖某条线索,或者换一个目标。", st.AuditAllowed, st.Findings)
	default:
		if reason != "" {
			text = "这一程结束了:" + reason
		} else {
			return
		}
	}
	if _, err := s.cfg.Store.AppendChat(ctx, eng.ID, "assistant", text, nil); err != nil {
		s.logger.Printf("youkai: summary message not stored: %v", err)
		return
	}
	s.hub.publish("chat", map[string]any{"type": "chat_summary", "engagement_id": eng.ID, "text": text})
}
