package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// The canary is youkai's own callback endpoint: a loopback listener that records
// "someone reached this URL" and nothing else.
//
// Why it exists: an SSRF or XXE probe can only be settled by observing the target
// make a request. The safe way to observe that is to be the destination - and then
// deliberately keep nothing: no bodies, no headers, no query strings beyond the
// token. A canary that stored what the target sent would be an exfiltration channel
// wearing a lab coat.
//
// Trust model: the token is 128 random bits, so a hit cannot be forged by guessing.
// The listener binds loopback only; a deployment that needs a public callback sets
// YOUKAI_CANARY_BASE to a tunnel it controls and forwards to that port.
type canary struct {
	mu    sync.Mutex
	srv   *http.Server
	port  int
	hits  map[string][]canaryHit
	ready chan struct{}
	once  sync.Once
}

type canaryHit struct {
	at     time.Time
	remote string
}

var (
	canaryOnce sync.Once
	canaryInst *canary
)

func canaryOf() *canary {
	canaryOnce.Do(func() {
		canaryInst = &canary{hits: map[string][]canaryHit{}, ready: make(chan struct{})}
	})
	return canaryInst
}

// start brings the listener up once. A failure is not fatal: probes then report
// "cannot judge" instead of pretending the target is not vulnerable.
func (c *canary) start() error {
	var err error
	c.once.Do(func() {
		ln, lerr := net.Listen("tcp", "127.0.0.1:0")
		if lerr != nil {
			err = lerr
			close(c.ready)
			return
		}
		c.mu.Lock()
		c.port = ln.Addr().(*net.TCPAddr).Port
		c.mu.Unlock()
		mux := http.NewServeMux()
		mux.HandleFunc("/c/", c.handle)
		c.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		close(c.ready)
		go func() { _ = c.srv.Serve(ln) }()
	})
	<-c.ready
	return err
}

// handle records a hit. It deliberately does not read the body: whatever the target
// sends stays in the socket buffer and is discarded when the connection closes.
func (c *canary) handle(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/c/")
	if token != "" {
		c.mu.Lock()
		c.hits[token] = append(c.hits[token], canaryHit{
			at:     time.Now(),
			remote: redactRemote(r.RemoteAddr),
		})
		c.mu.Unlock()
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok") // fixed body: this endpoint is not a data sink
}

// Token returns a fresh callback URL and its token.
func (c *canary) Token() (string, string, error) {
	if err := c.start(); err != nil {
		return "", "", err
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(buf)
	base := strings.TrimRight(os.Getenv("YOUKAI_CANARY_BASE"), "/")
	if base == "" {
		c.mu.Lock()
		port := c.port
		c.mu.Unlock()
		base = fmt.Sprintf("http://127.0.0.1:%d", port)
	}
	return base + "/c/" + token, token, nil
}

// Hits returns how many times a token was reached.
func (c *canary) Hits(token string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hits[token])
}

// Wait watches for a hit for a short window. False means "not observed", which the
// callers must report as "could not judge", never as "not vulnerable".
func (c *canary) Wait(token string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c.Hits(token) > 0 {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return c.Hits(token) > 0
}

// RemoteOf returns the first remote address seen for a token, already redacted to
// host level (no port, no headers).
func (c *canary) RemoteOf(token string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.hits[token]) == 0 {
		return ""
	}
	return c.hits[token][0].remote
}

func redactRemote(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
