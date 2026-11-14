package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"youkai/internal/engine"
	"youkai/internal/ledger"
)

// Settings is the persisted, NON-SECRET half of the LLM configuration.
//
// It is what the settings row's `value` column holds. The API key never appears
// here: either the operator names an environment variable, or the key lives in
// the encrypted blob next to this JSON.
type Settings struct {
	Enabled     bool    `json:"enabled"`
	BaseURL     string  `json:"base_url"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TimeoutS    int     `json:"timeout_s"`
	MaxTokens   int     `json:"max_tokens"`
	KeyFromEnv  string  `json:"key_from_env,omitempty"`
}

// Defaults applied when a field is left at zero.
const (
	DefaultTimeoutS    = 120
	DefaultMaxTokens   = 1200
	DefaultTemperature = 0
)

// Normalise fills safe defaults and trims strings.
func (s Settings) Normalise() Settings {
	s.BaseURL = strings.TrimRight(strings.TrimSpace(s.BaseURL), "/")
	s.Model = strings.TrimSpace(s.Model)
	s.KeyFromEnv = strings.TrimSpace(s.KeyFromEnv)
	if s.Temperature < 0 {
		s.Temperature = DefaultTemperature
	}
	if s.TimeoutS <= 0 {
		s.TimeoutS = DefaultTimeoutS
	}
	if s.MaxTokens <= 0 {
		s.MaxTokens = DefaultMaxTokens
	}
	if s.BaseURL == "" || s.Model == "" {
		// A half-configured model is "disabled", not "broken".
		s.Enabled = false
	}
	return s
}

// Validate rejects configurations that cannot work.
func (s Settings) Validate() error {
	if !strings.HasPrefix(s.BaseURL, "http://") && !strings.HasPrefix(s.BaseURL, "https://") {
		return fmt.Errorf("planner: base_url 必须是 http(s) URL")
	}
	if s.Model == "" {
		return fmt.Errorf("planner: model 不能为空")
	}
	if s.TimeoutS <= 0 || s.TimeoutS > 600 {
		return fmt.Errorf("planner: timeout_s 必须在 1..600 秒之间")
	}
	if s.MaxTokens <= 0 || s.MaxTokens > 32768 {
		return fmt.Errorf("planner: max_tokens 必须在 1..32768 之间")
	}
	if s.Temperature < 0 || s.Temperature > 2 {
		return fmt.Errorf("planner: temperature 必须在 0..2 之间")
	}
	if s.KeyFromEnv != "" && strings.ContainsAny(s.KeyFromEnv, " =") {
		return fmt.Errorf("planner: key_from_env 必须是环境变量名")
	}
	return nil
}

// ToConfig turns settings + an already-resolved key into a client config.
func (s Settings) ToConfig(key string) Config {
	return Config{
		BaseURL: s.BaseURL, APIKey: key, Model: s.Model,
		Temperature: s.Temperature,
		Timeout:     time.Duration(s.TimeoutS) * time.Second,
		MaxTokens:   s.MaxTokens,
	}
}

// Source says where the effective configuration came from.
type Source string

const (
	SourceSettings Source = "settings"
	SourceEnv      Source = "env"
	SourceDisabled Source = "disabled"
)

// Manager owns the live planner and swaps it atomically.
//
// The engine holds a stable reference (the Manager) for the lifetime of the
// process; a configuration change replaces the inner client. In-flight planner
// calls finish with the client they started with, so a save never aborts work.
type Manager struct {
	archive Archive

	mu     sync.RWMutex
	cfg    Config
	pl     *Planner
	source Source
	// keySource is "env:<NAME>" or "stored" or "".
	keySource string
}

// NewManager builds a disabled manager.
func NewManager(archive Archive) *Manager {
	return &Manager{archive: archive, source: SourceDisabled}
}

// Enabled reports whether a client is currently installed.
func (m *Manager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pl != nil
}

// Source reports where the configuration came from.
func (m *Manager) Source() Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.source
}

// KeySource reports "env:NAME", "stored", or "".
func (m *Manager) KeySource() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keySource
}

// Current returns the effective config with the key REDACTED. Never hand this to
// a caller that needs to authenticate; use the installer path instead.
func (m *Manager) Current() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg := m.cfg
	if cfg.APIKey != "" {
		cfg.APIKey = "<redacted>"
	}
	return cfg
}

// Install atomically replaces the live client. A nil/empty config disables it.
func (m *Manager) Install(cfg Config, source Source, keySource string) error {
	var pl *Planner
	if cfg.BaseURL != "" && cfg.Model != "" {
		built, err := New(Config{
			BaseURL: cfg.BaseURL, APIKey: cfg.APIKey, Model: cfg.Model,
			Temperature: cfg.Temperature, Timeout: cfg.Timeout, MaxTokens: cfg.MaxTokens,
			Archive: m.archive,
		})
		if err != nil {
			return err
		}
		pl = built
	}
	m.mu.Lock()
	m.cfg = cfg
	m.pl = pl
	m.source = source
	m.keySource = keySource
	m.mu.Unlock()
	return nil
}

// Disable removes the live client.
func (m *Manager) Disable() {
	m.mu.Lock()
	m.cfg = Config{}
	m.pl = nil
	m.source = SourceDisabled
	m.keySource = ""
	m.mu.Unlock()
}

// Propose implements engine.Proposer.
//
// When disabled it returns an error, and the API does not install the manager in
// that case; the error path exists so a mid-run disable degrades to "no proposal"
// rather than a panic.
func (m *Manager) Propose(ctx context.Context, req engine.ProposeRequest) ([]ledger.IntentSpec, error) {
	m.mu.RLock()
	pl := m.pl
	m.mu.RUnlock()
	if pl == nil {
		return nil, fmt.Errorf("planner: 未启用(未配置模型)")
	}
	return pl.Propose(ctx, req)
}

// Probe tests a configuration without touching the archive: it is a connectivity
// check, not a plan.
// Chat delegates to the installed planner, or reports that none is configured.
func (m *Manager) Chat(ctx context.Context, req ChatRequest) (ChatReply, error) {
	m.mu.Lock()
	p := m.pl
	m.mu.Unlock()
	if p == nil {
		return ChatReply{}, fmt.Errorf("planner: no model configured")
	}
	return p.Chat(ctx, req)
}

func (m *Manager) Probe(ctx context.Context, cfg Config) (time.Duration, error) {
	pl, err := New(Config{
		BaseURL: cfg.BaseURL, APIKey: cfg.APIKey, Model: cfg.Model,
		Temperature: cfg.Temperature, Timeout: cfg.Timeout, MaxTokens: 16,
		Archive: m.archive,
	})
	if err != nil {
		return 0, err
	}
	return pl.Probe(ctx)
}

// SeedFromEnv installs the environment configuration when one is present.
//
// Resolution order for the whole platform is: settings saved in the admin UI >
// environment variables > disabled. This method is the second step; the caller
// applies settings afterwards when they exist.
func (m *Manager) SeedFromEnv() bool {
	cfg, ok := FromEnv()
	if !ok {
		return false
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = time.Duration(DefaultTimeoutS) * time.Second
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = DefaultMaxTokens
	}
	_ = m.Install(cfg, SourceEnv, "env:"+EnvAPIKey)
	return true
}

// SettingsFromEnv renders the environment configuration as settings (for the UI to
// prefill) without installing anything.
func SettingsFromEnv() (Settings, bool) {
	base := strings.TrimSpace(os.Getenv(EnvBaseURL))
	model := strings.TrimSpace(os.Getenv(EnvModel))
	if base == "" || model == "" {
		return Settings{}, false
	}
	return Settings{
		Enabled: true, BaseURL: strings.TrimRight(base, "/"), Model: model,
		Temperature: DefaultTemperature, TimeoutS: DefaultTimeoutS, MaxTokens: DefaultMaxTokens,
		KeyFromEnv: EnvAPIKey,
	}.Normalise(), true
}

// MarshalSettings is a small helper for the API.
func MarshalSettings(s Settings) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
