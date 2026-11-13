// Command youkaid is the youkai control plane: one binary, one PostgreSQL pool,
// one loopback HTTP server, and the SPA embedded in it.
//
// Start it with the ledger DSN in the environment; it prints a URL that carries
// the local API token in the fragment, so the token never reaches a server log.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"youkai/internal/api"
	"youkai/internal/discipline"
	"youkai/internal/engine"
	"youkai/internal/gate"
	"youkai/internal/ledger"
	"youkai/internal/planner"
	"youkai/internal/runtime"
)

const (
	envDSN       = "YOUKAI_DSN"
	envAddr      = "YOUKAI_ADDR"
	envArtifacts = "YOUKAI_ARTIFACTS"
	envMaxSteps  = "YOUKAI_MAX_STEPS"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("youkaid: ")

	addr := flag.String("addr", envOr(envAddr, "127.0.0.1:8787"), "loopback listen address")
	dsn := flag.String("dsn", envOr(envDSN, ""), "PostgreSQL DSN (or "+envDSN+")")
	artifacts := flag.String("artifacts", envOr(envArtifacts, filepath.Join(".youkai", "artifacts")), "artifact root")
	accountsPath := flag.String("accounts", envOr("YOUKAI_ACCOUNTS", ".youkai/accounts.json"), "identity manifest (YoukaiAccounts/v1)")
	sessionDir := flag.String("sessions", envOr("YOUKAI_SESSIONS", ".youkai/sessions"), "encrypted session directory")
	maxSteps := flag.Int("max-steps", 10, "max steps per UI-triggered run")
	tokenFlag := flag.String("token", envOr("YOUKAI_TOKEN", ""), "API token (generated when empty)")
	tokenFile := flag.String("token-file", envOr("YOUKAI_TOKEN_FILE", ""), "write the API token here (0600)")
	noPlanner := flag.Bool("no-planner", false, "disable the LLM planner even if configured")
	flag.Parse()

	if strings.TrimSpace(*dsn) == "" {
		fatalf("no ledger DSN: set %s, e.g.\n  set %s=postgres://youkai:...@127.0.0.1:55432/youkai?sslmode=disable",
			envDSN, envDSN)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	store, err := ledger.Open(startCtx, *dsn)
	if err != nil {
		fatalf("%v", err)
	}
	defer store.Close()
	if err := store.Migrate(startCtx); err != nil {
		fatalf("migrate: %v", err)
	}
	cancel()

	if err := os.MkdirAll(*artifacts, 0o700); err != nil {
		fatalf("artifact dir: %v", err)
	}

	dispatcher := runtime.New(store, *artifacts)
	dispatcher.AccountsPath = *accountsPath
	dispatcher.SessionDir = *sessionDir

	// High-auth verification key: present means tier-2 execution against network
	// targets is possible at all. Absent means it is disabled, loudly.
	highAuthKey, keyErr := discipline.KeyFromEnv()
	if keyErr != nil {
		log.Printf("WARNING: %s is not set - tier-2 execution against network targets is DISABLED (approvals still record)", discipline.HighAuthKeyEnv)
	}

	// Optional planner.
	var proposer engine.Proposer
	llmInfo := api.LLMInfo{}
	if pcfg, ok := planner.FromEnv(); ok && !*noPlanner {
		pcfg.EngagementID = 0 // resolved per call by the runtime below
		pl, err := planner.New(planner.Config{
			BaseURL: pcfg.BaseURL, APIKey: pcfg.APIKey, Model: pcfg.Model,
			Temperature: pcfg.Temperature, Timeout: pcfg.Timeout, MaxTokens: pcfg.MaxTokens,
			Archive: store,
		})
		if err != nil {
			log.Printf("WARNING: planner disabled: %v", err)
		} else {
			proposer = pl
			info := planner.Describe(pcfg)
			llmInfo = api.LLMInfo{
				Enabled: true, BaseURL: info.BaseURL, Model: info.Model,
				KeyFromEnv: info.KeyFromEnv, KeyPresent: info.KeyPresent,
			}
			log.Printf("planner enabled: model=%s (every call is archived)", pcfg.Model)
		}
	}

	srv, err := api.New(api.Config{
		Addr:        *addr,
		Token:       *tokenFlag,
		Store:       store,
		Dispatcher:  dispatcher,
		ArtifactDir: *artifacts,
		HighAuthKey: highAuthKey,
		LLM:         llmInfo,
		Proposer:    proposer,
		PairSource:  pairSource{dispatcher},
		MaxSteps:    *maxSteps,
		Logger:      log.Default(),
	})
	if err != nil {
		fatalf("%v", err)
	}

	if strings.TrimSpace(*tokenFile) != "" {
		if err := os.WriteFile(*tokenFile, []byte(srv.Token()+"\n"), 0o600); err != nil {
			fatalf("write token file: %v", err)
		}
	}

	url := fmt.Sprintf("http://%s/#token=%s", *addr, srv.Token())
	log.Printf("open this URL in a browser (the token is in the fragment, not the request):")
	log.Printf("  %s", url)
	log.Printf("provider: %s", gate.Provider().Reason())
	log.Printf("planner: %v   high-auth: %v", llmInfo.Enabled, highAuthKey != "")
	if _, err := os.Stat(*accountsPath); err == nil {
		log.Printf("accounts: manifest %s   sessions %s", *accountsPath, *sessionDir)
	} else {
		log.Printf("accounts: no manifest at %s yet (the UI will show how to write one)", *accountsPath)
	}
	if strings.TrimSpace(os.Getenv("YOUKAI_SESSION_KEY")) == "" && strings.TrimSpace(os.Getenv("FAIRY_SESSION_KEY")) == "" {
		log.Printf("WARNING: no session key - login sessions will be stored base64 (equivalent to plaintext)")
	}
	fmt.Printf("\n  youkai  ->  %s\n\n", url)

	if err := srv.ListenAndServe(ctx); err != nil {
		fatalf("serve: %v", err)
	}
	log.Printf("stopped")
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "youkaid: "+format+"\n", args...)
	os.Exit(1)
}

// pairSource adapts the account layer's declared ownership to the engine's
// neutral pair type (so internal/engine stays free of account-package details).
type pairSource struct{ d *runtime.Dispatcher }

func (p pairSource) BolaPairs(ctx context.Context) ([]engine.AccessPair, error) {
	pairs, err := p.d.BolaPairs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]engine.AccessPair, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, engine.AccessPair{
			Owner: pair.Owner, Viewer: pair.Viewer, Marker: pair.Marker, URL: pair.URL,
		})
	}
	return out, nil
}
