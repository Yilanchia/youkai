package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"youkai/internal/config"
	"youkai/internal/planner"
)

// The LLM configuration endpoints.
//
// Three properties matter more than the feature:
//
//  1. The key is never echoed. Every read path reports only whether one exists
//     and where it comes from; `PUT` accepts a key but never returns it.
//  2. A saved config is hot-swapped: the engine holds the planner.Manager, so a
//     new run picks up the new model without a restart.
//  3. Changing how youkai talks to a model does NOT change what it may do to a
//     target. Tiers, approvals and the exploitation wall are untouched by these
//     endpoints, and the response says so.

// LLMView is what the UI may know about the LLM configuration.
type LLMView struct {
	Enabled     bool    `json:"enabled"`
	BaseURL     string  `json:"base_url"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TimeoutS    int     `json:"timeout_s"`
	MaxTokens   int     `json:"max_tokens"`
	// KeyPresent is true when a usable key exists (env value or stored secret).
	KeyPresent bool `json:"key_present"`
	// KeyFromEnv is the environment variable NAME, never its value.
	KeyFromEnv string `json:"key_from_env,omitempty"`
	// KeySource is "env:NAME", "stored", or "".
	KeySource string `json:"key_source,omitempty"`
	// Source is where the whole config came from: settings | env | disabled.
	Source string `json:"source"`
	// CanStoreSecrets tells the UI whether a directly-entered key can be saved.
	CanStoreSecrets bool       `json:"can_store_secrets"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
	UpdatedBy       string     `json:"updated_by,omitempty"`
}

// handleLLMConfig serves GET/PUT /api/config/llm.
func (s *Server) handleLLMConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		view, err := s.llmView(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		// Same shape as before, plus a `problem` field when the configured model did
		// not load. The view itself stays flat so existing clients keep working.
		writeJSON(w, http.StatusOK, llmViewWithProblem{LLMView: view, Problem: s.LLMProblem()})
	case http.MethodPut:
		s.putLLMConfig(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET or PUT")
	}
}

// putLLMRequest is the PUT body. Keys that are absent keep their current value,
// which is what lets the UI submit a form without re-entering a key.
type putLLMRequest struct {
	Enabled     *bool    `json:"enabled"`
	BaseURL     *string  `json:"base_url"`
	Model       *string  `json:"model"`
	Temperature *float64 `json:"temperature"`
	TimeoutS    *int     `json:"timeout_s"`
	MaxTokens   *int     `json:"max_tokens"`
	KeyFromEnv  *string  `json:"key_from_env"`
	// Key: absent = keep the stored secret, "" = clear it, otherwise store it.
	Key       *string `json:"key"`
	UpdatedBy string  `json:"updated_by"`
}

func (s *Server) putLLMConfig(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Settings == nil || s.cfg.Planner == nil {
		writeErr(w, http.StatusNotImplemented,
			"这台控制面没有配置存储(启动时未接线);请改用环境变量并在重启后生效")
		return
	}
	var body putLLMRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	current, _, cerr := s.storedLLMSettings(r.Context())
	next := current
	if cerr != nil && !errors.Is(cerr, config.ErrNotFound) {
		writeErr(w, http.StatusInternalServerError, "%v", cerr)
		return
	}
	if body.Enabled != nil {
		next.Enabled = *body.Enabled
	}
	if body.BaseURL != nil {
		next.BaseURL = *body.BaseURL
	}
	if body.Model != nil {
		next.Model = *body.Model
	}
	if body.Temperature != nil {
		next.Temperature = *body.Temperature
	}
	if body.TimeoutS != nil {
		next.TimeoutS = *body.TimeoutS
	}
	if body.MaxTokens != nil {
		next.MaxTokens = *body.MaxTokens
	}
	if body.KeyFromEnv != nil {
		next.KeyFromEnv = *body.KeyFromEnv
	}
	next = next.Normalise()

	directKey := ""
	hasDirectKey := body.Key != nil && strings.TrimSpace(*body.Key) != ""
	if next.KeyFromEnv != "" && hasDirectKey {
		writeErr(w, http.StatusBadRequest,
			"key 只能二选一:填 key_from_env(推荐,key 不落库)或直接填 key,不要同时填")
		return
	}
	if hasDirectKey {
		directKey = strings.TrimSpace(*body.Key)
	}

	// Asking to enable a model that is not usable is a bad request, not a silent
	// "disabled": Normalise() turns an incomplete config into Enabled=false, which
	// would otherwise look like the save worked.
	if body.Enabled != nil && *body.Enabled && !next.Enabled {
		writeErr(w, http.StatusBadRequest, "启用 LLM 需要 base_url 与 model")
		return
	}
	shouldEnable := next.Enabled
	if shouldEnable {
		if strings.TrimSpace(next.BaseURL) == "" || strings.TrimSpace(next.Model) == "" {
			writeErr(w, http.StatusBadRequest, "启用 LLM 需要 base_url 与 model")
			return
		}
		if err := next.Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
	}

	// Resolve the credential BEFORE persisting: an "enabled" configuration whose
	// key cannot be found must be refused, not saved as a half-config that leaves
	// the database and the process disagreeing.
	apiKey := ""
	keySource := ""
	switch {
	case next.KeyFromEnv != "":
		apiKey = strings.TrimSpace(os.Getenv(next.KeyFromEnv))
		keySource = "env:" + next.KeyFromEnv
		if apiKey == "" && shouldEnable {
			writeErr(w, http.StatusBadRequest,
				"环境变量 %s 在服务端为空:先导出它,或改为直接填 key;本次未保存", next.KeyFromEnv)
			return
		}
	case hasDirectKey:
		apiKey = directKey
		keySource = "stored"
	default:
		if s.cfg.Settings != nil {
			if k, err := s.cfg.Settings.GetSecret(r.Context(), config.KeyLLM); err == nil && k != "" {
				apiKey = k
				keySource = "stored"
			}
		}
	}
	if shouldEnable && apiKey == "" && !hasDirectKey && next.KeyFromEnv == "" {
		// Some local models need no key; say so instead of guessing.
		keySource = ""
	}

	// Storage semantics for the secret: nil keeps, "" clears, a value replaces.
	var secretPtr *string
	switch {
	case next.KeyFromEnv != "":
		// Switching to an environment reference retires the stored secret.
		empty := ""
		secretPtr = &empty
	case body.Key != nil && strings.TrimSpace(*body.Key) == "":
		empty := ""
		secretPtr = &empty
	case hasDirectKey:
		secretPtr = &directKey
	default:
		secretPtr = nil
	}

	if err := s.cfg.Settings.Put(r.Context(), config.KeyLLM,
		planner.MarshalSettings(next), secretPtr, byOr(body.UpdatedBy, "operator")); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, config.ErrSecretWithoutKey) {
			code = http.StatusPreconditionRequired
		}
		writeErr(w, code, "%v", err)
		return
	}

	// Now make it live.
	cfg := next.ToConfig(apiKey)
	if !shouldEnable {
		s.cfg.Planner.Disable()
	} else if err := s.cfg.Planner.Install(cfg, planner.SourceSettings, keySource); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	// Configuration changes are auditable. No secret goes into the detail.
	if err := s.cfg.Store.RecordConfigChange(r.Context(), "*", byOr(body.UpdatedBy, "operator"), "llm",
		viewOfSettings(current), viewOfSettings(next)); err != nil {
		// The change is live; report the audit failure rather than pretending.
		writeErr(w, http.StatusInternalServerError, "配置已生效,但审计写入失败:%v", err)
		return
	}

	view, _ := s.llmView(r.Context())
	writeJSON(w, http.StatusOK, llmViewWithProblem{LLMView: view, Problem: s.LLMProblem()})
}

// handleLLMTest runs one tiny completion against the given (or current) config.
func (s *Server) handleLLMTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if s.cfg.Planner == nil {
		writeErr(w, http.StatusNotImplemented, "这台控制面没有接线 planner")
		return
	}
	var body putLLMRequest
	_ = decodeJSON(w, r, &body)

	// Build the config to test: request body fields override the live one, so the
	// operator can try values before saving them.
	base := s.cfg.Planner.Current()
	settings := planner.Settings{
		Enabled: true, BaseURL: base.BaseURL, Model: base.Model,
		Temperature: base.Temperature, TimeoutS: int(base.Timeout.Seconds()), MaxTokens: base.MaxTokens,
	}
	if st, _, err := s.storedLLMSettings(r.Context()); err == nil {
		settings = st
	}
	if body.BaseURL != nil {
		settings.BaseURL = *body.BaseURL
	}
	if body.Model != nil {
		settings.Model = *body.Model
	}
	if body.Temperature != nil {
		settings.Temperature = *body.Temperature
	}
	if body.TimeoutS != nil {
		settings.TimeoutS = *body.TimeoutS
	}
	if body.MaxTokens != nil {
		settings.MaxTokens = *body.MaxTokens
	}
	if body.KeyFromEnv != nil {
		settings.KeyFromEnv = *body.KeyFromEnv
	}
	settings = settings.Normalise()
	if settings.BaseURL == "" || settings.Model == "" {
		writeErr(w, http.StatusBadRequest, "测试需要 base_url 与 model")
		return
	}
	if err := settings.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	key := ""
	source := ""
	if body.Key != nil && strings.TrimSpace(*body.Key) != "" {
		key = strings.TrimSpace(*body.Key)
		source = "request"
	} else if settings.KeyFromEnv != "" {
		key = os.Getenv(settings.KeyFromEnv)
		source = "env:" + settings.KeyFromEnv
	} else {
		var err error
		key, err = s.cfg.Settings.GetSecret(r.Context(), config.KeyLLM)
		if err != nil && !errors.Is(err, config.ErrNotFound) {
			writeErr(w, http.StatusPreconditionRequired, "%v", err)
			return
		}
		if key != "" {
			source = "stored"
		}
	}

	// A connect test with no key is still meaningful (some local models need none),
	// but say so rather than letting the operator guess.
	cfg := settings.ToConfig(key)
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(settings.TimeoutS)*time.Second)
	defer cancel()
	latency, err := s.cfg.Planner.Probe(ctx, cfg)

	resp := map[string]any{
		"ok":         err == nil,
		"latency_ms": latency.Milliseconds(),
		"base_url":   settings.BaseURL,
		"model":      settings.Model,
		"key_source": source,
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- helpers ---------------------------------------------------------------

// llmView builds the redacted view from the live manager + stored settings.
func (s *Server) llmView(ctx context.Context) (LLMView, error) {
	view := LLMView{CanStoreSecrets: s.cfg.Settings != nil && s.cfg.Settings.CanStoreSecrets()}
	if s.cfg.Planner != nil {
		cur := s.cfg.Planner.Current()
		view.Enabled = s.cfg.Planner.Enabled()
		view.BaseURL = cur.BaseURL
		view.Model = cur.Model
		view.Temperature = cur.Temperature
		view.TimeoutS = int(cur.Timeout.Seconds())
		view.MaxTokens = cur.MaxTokens
		view.Source = string(s.cfg.Planner.Source())
		view.KeySource = s.cfg.Planner.KeySource()
	}
	if s.cfg.Settings != nil {
		if st, hasSecret, err := s.storedLLMSettings(ctx); err == nil {
			view.KeyFromEnv = st.KeyFromEnv
			view.KeyPresent = hasSecret || (st.KeyFromEnv != "" && os.Getenv(st.KeyFromEnv) != "")
			if at, by, merr := s.cfg.Settings.Meta(ctx, config.KeyLLM); merr == nil {
				t := at
				view.UpdatedAt = &t
				view.UpdatedBy = by
			}
		}
	}
	if view.KeyFromEnv != "" && os.Getenv(view.KeyFromEnv) != "" {
		view.KeyPresent = true
	}
	return view, nil
}

func (s *Server) storedLLMSettings(ctx context.Context) (planner.Settings, bool, error) {
	if s.cfg.Settings == nil {
		return planner.Settings{}, false, config.ErrNotFound
	}
	raw, hasSecret, err := s.cfg.Settings.Get(ctx, config.KeyLLM)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return planner.Settings{}, false, nil
		}
		return planner.Settings{}, false, err
	}
	var st planner.Settings
	if err := json.Unmarshal(raw, &st); err != nil {
		return planner.Settings{}, hasSecret, err
	}
	return st.Normalise(), hasSecret, nil
}

// resolveLLMKey decides which credential the process should use.
func (s *Server) resolveLLMKey(ctx context.Context, st planner.Settings) (string, string, error) {
	if st.KeyFromEnv != "" {
		v := strings.TrimSpace(os.Getenv(st.KeyFromEnv))
		if v == "" {
			return "", "env:" + st.KeyFromEnv, errors.New(
				"环境变量 " + st.KeyFromEnv + " 为空;请先导出它,或改为直接填 key")
		}
		return v, "env:" + st.KeyFromEnv, nil
	}
	if s.cfg.Settings == nil {
		return "", "", nil
	}
	key, err := s.cfg.Settings.GetSecret(ctx, config.KeyLLM)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return "", "", nil
		}
		return "", "", err
	}
	if key != "" {
		return key, "stored", nil
	}
	return "", "", nil
}

// viewOfSettings is the audit detail: no secret, only the knobs.
func viewOfSettings(st planner.Settings) map[string]any {
	return map[string]any{
		"enabled": st.Enabled, "base_url": st.BaseURL, "model": st.Model,
		"temperature": st.Temperature, "timeout_s": st.TimeoutS, "max_tokens": st.MaxTokens,
		"key_from_env": st.KeyFromEnv,
	}
}

func byOr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return strings.TrimSpace(s)
}

// installLLMFromStore loads the persisted configuration at startup.
//
// Order: settings saved in the UI > environment variables > disabled. A broken
// stored config disables the planner with a log line instead of failing startup:
// the deterministic loop does not depend on the model.
func (s *Server) installLLMFromStore(ctx context.Context) error {
	if s.cfg.Planner == nil {
		return nil
	}
	st, hasSecret, err := s.storedLLMSettings(ctx)
	if err != nil {
		// Remember WHY, so the UI can say "the stored key cannot be decrypted"
		// instead of quietly running without a planner. This is what turns a silent
		// "planner: false" in the log into something the operator can act on.
		s.setLLMProblem("已保存的模型 key 解不开(会话密钥换过?):" + err.Error() +
			"。请在「设置」里重新填一次 key,或改用环境变量引用。")
	}
	if err == nil && (hasSecret || st.BaseURL != "" || st.Model != "") {
		st = st.Normalise()
		key, source, kerr := s.resolveLLMKey(ctx, st)
		if kerr != nil {
			// The row is there but the secret cannot be opened (the session key
			// changed) - the single most confusing state for an operator, so it gets
			// a sentence they can act on instead of a silent "planner: false".
			s.setLLMProblem("已保存的模型 key 解不开(会话密钥换过?):" + kerr.Error() +
				"。请在「设置」里重新填一次 key,或改用环境变量引用。")
			return kerr
		}
		if st.Enabled {
			if verr := st.Validate(); verr != nil {
				return verr
			}
		}
		cfg := st.ToConfig(key)
		if !st.Enabled {
			s.cfg.Planner.Disable()
			return nil
		}
		if err := s.cfg.Planner.Install(cfg, planner.SourceSettings, source); err != nil {
			s.setLLMProblem("模型配置没有装上去:" + err.Error())
			return err
		}
		s.setLLMProblem("")
		return nil
	}
	// No stored settings: fall back to the environment, then disabled. Do NOT clear
	// the problem here: if the stored secret failed to decrypt, that reason is the
	// only thing that explains why the planner is off, and the fallback would wipe it.
	s.cfg.Planner.SeedFromEnv()
	return nil
}

// llmMu guards llmProblem, which is a human-readable reason the configured model
// did not load (a key that no longer decrypts, a rejected config, ...).
func (s *Server) setLLMProblem(msg string) {
	s.llmMu.Lock()
	s.llmProblem = msg
	s.llmMu.Unlock()
}

// LLMProblem returns the last load failure, if any.
func (s *Server) LLMProblem() string {
	s.llmMu.Lock()
	defer s.llmMu.Unlock()
	return s.llmProblem
}

// llmViewWithProblem is the wire shape of GET /api/config/llm.
//
// The view stays flat (the fields the UI already reads) and `problem` explains a
// configuration that exists but could not be loaded.
type llmViewWithProblem struct {
	LLMView
	Problem string `json:"problem,omitempty"`
}
