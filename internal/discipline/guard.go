package discipline

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Auditor receives one row per attempted request. The ledger implements it.
//
// The audit row is written when the outcome is known (as Fairy does), and the
// write is checked: if it fails, the response is discarded and the guard returns
// an error, so nothing lands in the ledger that has no audit trail. The residual
// window is one request whose bytes left the machine but could not be recorded;
// the alternative (pre-send rows in an append-only table) would leave every row
// permanently incomplete.
type Auditor interface {
	Record(ctx context.Context, ev AuditEvent) error
}

// AuditEvent is one attempt, allowed or blocked. Append-only.
type AuditEvent struct {
	RequestID  string         `json:"request_id"`
	Engagement string         `json:"engagement"`
	TS         time.Time      `json:"ts"`
	Method     string         `json:"method"`
	URL        string         `json:"url"`
	Host       string         `json:"host"`
	Status     int            `json:"status"`
	Bytes      int64          `json:"bytes"`
	Verdict    string         `json:"verdict"` // allowed | blocked | error
	Reason     string         `json:"reason"`
	Purpose    string         `json:"purpose"`
	DurationMS int64          `json:"duration_ms"`
	Detail     map[string]any `json:"detail,omitempty"`
}

// Verdicts recorded in the audit trail.
const (
	VerdictAllowed = "allowed"
	VerdictBlocked = "blocked"
	VerdictError   = "error"
)

// Request is one outbound HTTP request, as a capability asks for it.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	// Session is an optional label for the credential profile to attach. The
	// guard does not resolve it; the caller passes concrete headers.
	Session string
	// Purpose names the capability, so the audit trail says why bytes moved.
	Purpose string
	// FollowRedirects re-checks scope at every hop when true.
	FollowRedirects bool
	// MaxBytes overrides the passport's body cap for this request.
	MaxBytes int64
	// Timeout overrides the passport's per-request timeout.
	Timeout time.Duration
}

// Hop records one redirect step.
type Hop struct {
	URL       string `json:"url"`
	Status    int    `json:"status"`
	RequestID string `json:"request_id"`
	Blocked   bool   `json:"blocked,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// TLSInfo is the negotiated transport security, kept minimal.
type TLSInfo struct {
	Version   string `json:"version"`
	Cipher    string `json:"cipher"`
	Server    string `json:"server,omitempty"`
	Verified  bool   `json:"verified"`
	NotAfter  string `json:"not_after,omitempty"`
	PeerCerts int    `json:"peer_certs"`
}

// Response is what a capability gets back. It is the ONLY shape target data
// takes inside youkai.
type Response struct {
	RequestID   string            `json:"request_id"`
	URL         string            `json:"url"`
	FinalURL    string            `json:"final_url"`
	Method      string            `json:"method"`
	Status      int               `json:"status"`
	StatusText  string            `json:"status_text"`
	Header      map[string]string `json:"headers,omitempty"` // sanitised
	ContentType string            `json:"content_type,omitempty"`
	Body        []byte            `json:"-"` // in-memory only; never persisted
	BodyBytes   int64             `json:"body_bytes"`
	Truncated   bool              `json:"truncated,omitempty"`
	Redirects   []Hop             `json:"redirects,omitempty"`
	TLS         *TLSInfo          `json:"tls,omitempty"`
	TimingMS    int64             `json:"timing_ms"`
}

// Text returns the body as a string (bounded by the passport's cap).
func (r *Response) Text() string {
	if r == nil {
		return ""
	}
	return string(r.Body)
}

// Snippet returns at most n leading characters of the body, for a judgement.
// Capabilities pass this into facts; the full body never leaves memory.
func (r *Response) Snippet(n int) string {
	if r == nil || n <= 0 {
		return ""
	}
	if len(r.Body) <= n {
		return string(r.Body)
	}
	return string(r.Body[:n])
}

// Guard is the single egress point. Every target request in youkai goes through
// Do, which is why the scope is enforced rather than trusted.
type Guard struct {
	engagement string
	auditor    Auditor

	mu    sync.Mutex
	scope *Scope
	used  int
	seq   int
	// limiter state
	tokens float64
	last   time.Time

	client    *http.Client
	transport *http.Transport

	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// GuardOptions tunes construction (tests inject a clock).
type GuardOptions struct {
	Now   func() time.Time
	Sleep func(context.Context, time.Duration) error
}

// NewGuard builds a guard for one engagement. A nil or invalid scope is a hard
// error: youkai does not run without a passport.
func NewGuard(scope *Scope, engagement string, auditor Auditor) (*Guard, error) {
	if scope == nil {
		return nil, ErrNoScope
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if auditor == nil {
		return nil, errors.New("discipline: an auditor is required (no audit, no request)")
	}
	if strings.TrimSpace(engagement) == "" {
		engagement = scope.Project
	}
	g := &Guard{
		engagement: engagement,
		auditor:    auditor,
		scope:      scope,
		tokens:     scope.RPS,
		last:       time.Now(),
		now:        time.Now,
		sleep:      sleepCtx,
	}
	g.rebuildClient()
	return g, nil
}

// WithOptions overrides the clock (tests).
func (g *Guard) WithOptions(o GuardOptions) *Guard {
	if o.Now != nil {
		g.now = o.Now
	}
	if o.Sleep != nil {
		g.sleep = o.Sleep
	}
	return g
}

// Scope returns the current passport (read-only use; SetScope swaps atomically).
func (g *Guard) Scope() *Scope {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.scope
}

// SetScope swaps the passport and resets budgets. Used when a human re-authorises.
func (g *Guard) SetScope(s *Scope) error {
	if err := s.Validate(); err != nil {
		return err
	}
	g.mu.Lock()
	g.scope = s
	g.tokens = s.RPS
	g.last = g.now()
	g.used = 0
	g.mu.Unlock()
	g.rebuildClient()
	return nil
}

// Used is the number of requests attempted (including blocked ones).
func (g *Guard) Used() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.used
}

// rebuildClient installs the transport with the SSRF guard. The dial Control
// callback sees the RESOLVED address, so a hostname cannot rebind its way into
// the private network after the URL check passed.
func (g *Guard) rebuildClient() {
	scope := g.scope

	tr := &http.Transport{
		Proxy:                 nil, // never route target traffic through an ambient proxy
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !scope.VerifyTLS,
			MinVersion:         tls.VersionTLS12,
		},
	}
	tr.DialContext = newScopedDialer(scope, 10*time.Second).DialContext

	jar, _ := cookiejar.New(nil)
	g.transport = tr
	g.client = &http.Client{
		Transport: tr,
		Jar:       jar,
		// Redirects are followed manually so each hop is re-checked and audited.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Do performs one logical request, following redirects hop by hop under the
// passport's rules.
func (g *Guard) Do(ctx context.Context, req Request) (*Response, error) {
	if strings.TrimSpace(req.URL) == "" {
		return nil, fmt.Errorf("discipline: empty url")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}

	start := g.now()
	var hops []Hop
	current := req.URL
	maxHops := g.scope.MaxRedirects
	var lastErr error

	for hopIndex := 0; hopIndex <= maxHops; hopIndex++ {
		if err := g.admit(ctx, method, current, req.Purpose); err != nil {
			// admit() already audited the refusal.
			return nil, err
		}

		requestID := g.nextRequestID()
		resp, body, truncated, finalURL, err := g.roundTrip(ctx, requestID, method, current, req)
		if err != nil {
			lastErr = err
			break // audited inside roundTrip
		}

		isRedirect := resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != ""
		if !isRedirect || !req.FollowRedirects {
			return g.finish(resp, body, truncated, current, finalURL, requestID, hops, start), nil
		}

		next, err := resolveLocation(current, resp.Header.Get("Location"))
		_ = resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("discipline: bad redirect target: %w", err)
			break
		}
		hops = append(hops, Hop{URL: current, Status: resp.StatusCode, RequestID: requestID})

		// Re-check the next hop BEFORE following it. A redirect out of scope
		// stops the chain here, and the refusal is audited.
		nextDec, err := g.scope.Check(next)
		if err != nil {
			_ = g.audit(ctx, AuditEvent{
				RequestID:  g.nextRequestID(),
				Engagement: g.engagement,
				TS:         g.now().UTC(),
				Method:     method,
				URL:        next,
				Host:       nextDec.Host,
				Verdict:    VerdictBlocked,
				Reason:     "redirect target out of scope: " + err.Error(),
				Purpose:    req.Purpose,
				Detail:     map[string]any{"parent_request_id": requestID, "hop": hopIndex + 1},
			})
			hops = append(hops, Hop{URL: next, Blocked: true, Reason: "out of scope: " + err.Error()})
			return nil, fmt.Errorf("%w: redirect to %s", ErrOutOfScope, next)
		}
		current = next
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("discipline: redirect chain exceeded %d hops", maxHops)
	}
	return nil, lastErr
}

// admit enforces expiry, method, scope, budget and rate; it audits refusals.
func (g *Guard) admit(ctx context.Context, method, rawURL, purpose string) error {
	g.mu.Lock()
	scope := g.scope
	g.mu.Unlock()

	refuse := func(format string, args ...any) error {
		reason := fmt.Sprintf(format, args...)
		dec, _ := scope.Check(rawURL)
		_ = g.audit(ctx, AuditEvent{
			RequestID:  g.nextRequestID(),
			Engagement: g.engagement,
			TS:         g.now().UTC(),
			Method:     method,
			URL:        rawURL,
			Host:       dec.Host,
			Verdict:    VerdictBlocked,
			Reason:     reason,
			Purpose:    purpose,
		})
		return errors.New("discipline: " + reason)
	}

	if scope.Expired(g.now()) {
		return refuse("scope passport expired at %s", scope.ExpiresAt.Format(time.RFC3339))
	}
	if !scope.MethodAllowed(method) {
		return refuse("method %s is not authorised", method)
	}
	if _, err := scope.Check(rawURL); err != nil {
		return refuse("%v", err)
	}

	g.mu.Lock()
	used := g.used
	scope = g.scope
	g.mu.Unlock()
	if used >= scope.MaxRequests {
		return refuse("request budget exhausted (%d)", scope.MaxRequests)
	}

	// Token bucket: one token per request, refilled at scope.RPS.
	g.mu.Lock()
	now := g.now()
	elapsed := now.Sub(g.last).Seconds()
	if elapsed > 0 {
		g.tokens += elapsed * scope.RPS
		if g.tokens > scope.RPS {
			g.tokens = scope.RPS
		}
		g.last = now
	}
	wait := 0.0
	if g.tokens < 1 {
		wait = (1 - g.tokens) / scope.RPS
	} else {
		g.tokens--
		g.used++
	}
	g.mu.Unlock()

	if wait > 0 {
		if err := g.sleep(ctx, time.Duration(wait*float64(time.Second))); err != nil {
			return refuse("rate limiter interrupted: %v", err)
		}
		g.mu.Lock()
		g.tokens = 0
		g.last = g.now()
		g.used++
		g.mu.Unlock()
	}
	return nil
}

// roundTrip sends exactly one HTTP request and audits the outcome.
//
// The body is returned, not stashed on the guard: a guard is shared by concurrent
// workers, and evidence must never be "whoever wrote last".
func (g *Guard) roundTrip(ctx context.Context, requestID, method, rawURL string, req Request) (*http.Response, []byte, bool, string, error) {
	scope := g.Scope()
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = time.Duration(scope.TimeoutMS) * time.Millisecond
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var body io.Reader
	if len(req.Body) > 0 {
		body = strings.NewReader(string(req.Body))
	}
	httpReq, err := http.NewRequestWithContext(rctx, method, rawURL, body)
	if err != nil {
		_ = g.audit(ctx, AuditEvent{
			RequestID: requestID, Engagement: g.engagement, TS: g.now().UTC(),
			Method: method, URL: rawURL, Verdict: VerdictError,
			Reason: "build request: " + err.Error(), Purpose: req.Purpose,
		})
		return nil, nil, false, "", err
	}
	httpReq.Header.Set("User-Agent", "youkai/0.2 (+authorised-engagement)")
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	// Never let a capability smuggle a Host/authority override past the scope check.
	if httpReq.Host != "" && !strings.EqualFold(httpReq.Host, httpReq.URL.Host) {
		httpReq.Host = ""
	}

	started := g.now()
	resp, err := g.client.Do(httpReq)
	duration := g.now().Sub(started)
	if err != nil {
		_ = g.audit(ctx, AuditEvent{
			RequestID: requestID, Engagement: g.engagement, TS: started.UTC(),
			Method: method, URL: rawURL, Host: HostOf(rawURL), Verdict: VerdictError,
			Reason: classifyNetErr(err), Purpose: req.Purpose,
			DurationMS: duration.Milliseconds(),
		})
		return nil, nil, false, "", fmt.Errorf("discipline: %s %s: %w", method, rawURL, err)
	}

	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		maxBytes = scope.MaxBytes
	}
	limited := io.LimitReader(resp.Body, maxBytes+1)
	bodyBytes, readErr := io.ReadAll(limited)
	truncated := false
	if int64(len(bodyBytes)) > maxBytes {
		bodyBytes = bodyBytes[:maxBytes]
		truncated = true
	}
	_ = resp.Body.Close()
	if readErr != nil {
		resp.Body = io.NopCloser(strings.NewReader(""))
		_ = g.audit(ctx, AuditEvent{
			RequestID: requestID, Engagement: g.engagement, TS: started.UTC(),
			Method: method, URL: rawURL, Host: HostOf(rawURL), Status: resp.StatusCode,
			Bytes: int64(len(bodyBytes)), Verdict: VerdictError,
			Reason: "read body: " + readErr.Error(), Purpose: req.Purpose,
			DurationMS: duration.Milliseconds(),
		})
		return nil, nil, false, "", fmt.Errorf("discipline: read body: %w", readErr)
	}

	resp.Body = io.NopCloser(strings.NewReader(""))

	if err := g.audit(ctx, AuditEvent{
		RequestID: requestID, Engagement: g.engagement, TS: started.UTC(),
		Method: method, URL: rawURL, Host: HostOf(rawURL), Status: resp.StatusCode,
		Bytes: int64(len(bodyBytes)), Verdict: VerdictAllowed,
		Purpose: req.Purpose, DurationMS: duration.Milliseconds(),
		Detail: map[string]any{"content_type": resp.Header.Get("Content-Type"), "truncated": truncated},
	}); err != nil {
		return nil, nil, false, "", fmt.Errorf("discipline: audit failed, refusing to continue: %w", err)
	}
	return resp, bodyBytes, truncated, resp.Request.URL.String(), nil
}

// finish assembles the Response the caller sees.
func (g *Guard) finish(resp *http.Response, body []byte, truncated bool, requestURL, finalURL, requestID string, hops []Hop, start time.Time) *Response {
	out := &Response{
		RequestID:   requestID,
		URL:         requestURL,
		FinalURL:    finalURL,
		Method:      resp.Request.Method,
		Status:      resp.StatusCode,
		StatusText:  http.StatusText(resp.StatusCode),
		Header:      SanitizeHeaders(resp.Header),
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		BodyBytes:   int64(len(body)),
		Truncated:   truncated,
		Redirects:   hops,
		TimingMS:    g.now().Sub(start).Milliseconds(),
	}
	if resp.TLS != nil {
		out.TLS = &TLSInfo{
			Version:   tlsVersionName(resp.TLS.Version),
			Cipher:    tls.CipherSuiteName(resp.TLS.CipherSuite),
			Server:    resp.TLS.ServerName,
			Verified:  len(resp.TLS.VerifiedChains) > 0,
			PeerCerts: len(resp.TLS.PeerCertificates),
		}
		if len(resp.TLS.PeerCertificates) > 0 {
			out.TLS.NotAfter = resp.TLS.PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
		}
	}
	_ = resp.Body.Close()
	return out
}

// ---- audit + ids -----------------------------------------------------------

func (g *Guard) audit(ctx context.Context, ev AuditEvent) error {
	return g.auditor.Record(ctx, ev)
}

func (g *Guard) nextRequestID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seq++
	var b [2]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("R%04d-%s", g.seq, hex.EncodeToString(b[:]))
}

// ---- helpers ---------------------------------------------------------------

// SanitizeHeaders keeps the security-relevant headers and drops credential
// values. Evidence needs to know that Set-Cookie existed; it does not need the
// session token.
func SanitizeHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		lk := strings.ToLower(k)
		switch lk {
		case "set-cookie":
			// Keep the cookie NAME and its attributes; redact only the value.
			// A cookie-flag check needs HttpOnly/Secure/SameSite to exist in the
			// evidence, and the value is the only secret part.
			redacted := make([]string, 0, len(v))
			for _, c := range v {
				redacted = append(redacted, redactSetCookie(c))
			}
			out[k] = strings.Join(redacted, "; ")
		case "authorization", "proxy-authorization", "cookie":
			out[k] = "<redacted>"
		default:
			out[k] = strings.Join(v, ", ")
		}
	}
	return out
}

// redactSetCookie keeps the name and flags, drops the value.
//
// "sid=<redacted>; HttpOnly; Secure; SameSite=Strict" is exactly what a
// cookie-flag finding needs to cite, and it is not a credential.
func redactSetCookie(raw string) string {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return "<redacted>"
	}
	head := strings.TrimSpace(parts[0])
	name := head
	if n, _, ok := strings.Cut(head, "="); ok {
		name = strings.TrimSpace(n)
	}
	out := []string{name + "=<redacted>"}
	for _, attr := range parts[1:] {
		attr = strings.TrimSpace(attr)
		if attr == "" {
			continue
		}
		// An attribute value can be sensitive (rare), a flag name cannot.
		if an, av, ok := strings.Cut(attr, "="); ok {
			out = append(out, strings.TrimSpace(an)+"="+strings.TrimSpace(av))
		} else {
			out = append(out, attr)
		}
	}
	return strings.Join(out, "; ")
}

func resolveLocation(base, loc string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	l, err := url.Parse(loc)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(l).String(), nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func classifyNetErr(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns: " + dnsErr.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if strings.Contains(err.Error(), "certificate") {
		return "tls: certificate verification failed"
	}
	return "transport: " + err.Error()
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
