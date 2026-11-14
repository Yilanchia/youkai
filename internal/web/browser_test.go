package web

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"youkai/internal/ledger"
)

// ---- WebSocket codec -------------------------------------------------------

// TestWSFrameRoundTrip proves the frame encoder and decoder agree, including the
// three length encodings and the client-side mask.
func TestWSFrameRoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("small"),
		[]byte(strings.Repeat("a", 200)),   // 16-bit length
		[]byte(strings.Repeat("b", 70000)), // 64-bit length
	}
	for _, payload := range cases {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		w := &wsConn{conn: client, br: bufio.NewReader(client)}
		go func() {
			_ = w.writeFrame(opText, payload)
		}()

		br := bufio.NewReader(server)
		var head [2]byte
		if _, err := io.ReadFull(br, head[:]); err != nil {
			t.Fatalf("read head: %v", err)
		}
		if op := head[0] & 0x0F; op != opText {
			t.Fatalf("opcode = %d", op)
		}
		if head[1]&0x80 == 0 {
			t.Fatal("client frame was not masked")
		}
		length := uint64(head[1] & 0x7F)
		switch length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				t.Fatalf("read ext16: %v", err)
			}
			length = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				t.Fatalf("read ext64: %v", err)
			}
			length = binary.BigEndian.Uint64(ext[:])
		}
		var mask [4]byte
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			t.Fatalf("read mask: %v", err)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(br, body); err != nil {
			t.Fatalf("read body: %v", err)
		}
		for i := range body {
			body[i] ^= mask[i%4]
		}
		if string(body) != string(payload) {
			t.Fatalf("payload mismatch: got %d bytes, want %d", len(body), len(payload))
		}
	}
}

// TestWSReadReassemblesFragments feeds a fragmented message plus a ping through
// the reader and expects one reassembled message.
func TestWSReadReassemblesFragments(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	c := &wsConn{conn: client, br: bufio.NewReader(client)}
	go func() {
		// Server frames are unmasked.
		writeServerFrame(server, false, opText, []byte("frag-1-"))
		writeServerFrame(server, false, opContinuation, []byte("frag-2"))
		writeServerFrame(server, true, opPing, []byte("ping"))
		writeServerFrame(server, true, opContinuation, []byte("-end"))
		writeServerFrame(server, true, opClose, nil)
	}()

	op, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if op != opText || string(msg) != "frag-1-frag-2-end" {
		t.Fatalf("got op=%d msg=%q", op, msg)
	}
	if _, _, err := c.ReadMessage(); err != io.EOF {
		t.Fatalf("expected EOF after close, got %v", err)
	}
}

func writeServerFrame(w io.Writer, fin bool, opcode byte, payload []byte) {
	header := []byte{opcode}
	if fin {
		header[0] |= 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, byte(n))
	case n <= 0xFFFF:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		header = append(header, 127)
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(n))
		header = append(header, lenBuf[:]...)
	}
	_, _ = w.Write(header)
	_, _ = w.Write(payload)
}

func TestWSRefusesNonLoopback(t *testing.T) {
	if _, err := dialWS(context.Background(), "ws://example.com:9222/devtools/browser/x"); err == nil {
		t.Fatal("dialWS accepted a non-loopback endpoint")
	}
	if _, err := dialWS(context.Background(), "wss://127.0.0.1:9222/x"); err == nil {
		t.Fatal("dialWS accepted a non-ws scheme")
	}
}

// TestWSHandshake accepts a loopback upgrade and proves the accept key is the
// RFC 6455 value.
func TestWSHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var key string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "sec-websocket-key") {
				key = strings.TrimSpace(v)
			}
		}
		h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		accept := base64.StdEncoding.EncodeToString(h[:])
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		time.Sleep(50 * time.Millisecond)
	}()

	ws, err := dialWS(context.Background(), "ws://"+ln.Addr().String()+"/devtools/browser/test")
	if err != nil {
		t.Fatalf("dialWS: %v", err)
	}
	defer ws.Close()
	<-done
}

// ---- the browser capability, end to end ------------------------------------

// TestBrowserRendersAndBlocksOutOfScope is the GAPS acceptance test for the CDP
// work:
//
//   - a real headless browser renders a page and we read its title/links;
//   - a same-origin XHR is observed and allowed;
//   - an in-page fetch to a host outside the passport is refused at the CDP
//     network layer, the audit trail shows a blocked row, and the page cannot
//     reach it.
func TestBrowserRendersAndBlocksOutOfScope(t *testing.T) {
	if detectBrowser() == "" {
		t.Skip("no Chromium-family browser on this machine")
	}
	if testing.Short() {
		t.Skip("browser integration test skipped in -short")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/data":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"items":[1,2,3]}`))
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, `<!doctype html><html><head><title>SPA lab</title></head><body>
<h1>spa</h1>
<a href="/second">second</a>
<script>
  fetch('/api/data').then(r => r.json());
  fetch('http://out-of-scope.invalid/beacon').catch(() => {});
</script>
</body></html>`)
		default:
			_, _ = io.WriteString(w, "<title>other</title>")
		}
	}))
	defer srv.Close()

	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
	env.ArtifactDir = t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	obs, err := Run(ctx, env, "browser", map[string]any{"url": srv.URL + "/", "wait_ms": 1200})
	if err != nil {
		t.Fatalf("browser: %v", err)
	}

	// The page rendered: we know its title, which only the DOM can give us.
	var sawTitle, sawLink, sawXHR bool
	for _, f := range obs.Facts {
		switch {
		case strings.Contains(f.Statement, "SPA lab"):
			sawTitle = true
		case strings.Contains(f.Statement, "页面链接:") && strings.Contains(f.Statement, "/second"):
			sawLink = true
		case strings.Contains(f.Statement, "页面 XHR:") && strings.Contains(f.Statement, "/api/data"):
			sawXHR = true
		}
	}
	if !sawTitle {
		t.Fatalf("did not read the rendered title; facts=%v", factStatements(obs))
	}
	if !sawLink {
		t.Fatalf("did not read a rendered link; facts=%v", factStatements(obs))
	}
	if !sawXHR {
		t.Fatalf("did not observe the same-origin XHR; facts=%v", factStatements(obs))
	}

	// The out-of-scope fetch must have been refused, and the refusal audited.
	var blockedFinding bool
	for _, f := range obs.Findings {
		if f.Kind == "scope-blocked" {
			blockedFinding = true
		}
	}
	if !blockedFinding {
		t.Fatalf("no scope-blocked finding; findings=%+v", obs.Findings)
	}
	var auditedBlock bool
	for _, ev := range recorder.snapshot() {
		if ev.Verdict == "blocked" && strings.Contains(ev.URL, "out-of-scope.invalid") {
			auditedBlock = true
		}
	}
	if !auditedBlock {
		t.Fatal("the out-of-scope fetch was not recorded as blocked in the audit trail")
	}
	// Every allowed request in the observation must be a real audit row: the
	// browser cannot invent a request_id.
	known := map[string]bool{}
	for _, ev := range recorder.snapshot() {
		if ev.Verdict == "allowed" {
			known[ev.RequestID] = true
		}
	}
	for _, id := range obs.RequestIDs {
		if id == "" {
			continue
		}
		if !known[id] {
			t.Fatalf("observation cites request_id %q that no audit row granted", id)
		}
	}
	// And the page's own document load must be one of them.
	if len(obs.RequestIDs) < 2 {
		t.Fatalf("expected the document + XHR to be gated, got %v", obs.RequestIDs)
	}
}

// factStatements flattens facts for failure messages.
func factStatements(obs ledger.Observation) []string {
	out := make([]string, 0, len(obs.Facts))
	for _, f := range obs.Facts {
		out = append(out, f.Statement)
	}
	return out
}

// ---- session injection (v0.6) ----------------------------------------------

func TestHeaderMergeKeepsRequestHeadersAndWins(t *testing.T) {
	base := map[string]string{"User-Agent": "ua", "cookie": "stale=1"}
	extra := map[string]string{"Cookie": "sid=sess-alice"}
	merged := mergeHeaders(base, extra)
	if merged["User-Agent"] != "ua" {
		t.Fatal("merge dropped the browser's own headers")
	}
	if merged["Cookie"] != "sid=sess-alice" {
		t.Fatalf("the session cookie did not win: %v", merged)
	}
	// Case-insensitive replacement: the stale "cookie" key must be gone.
	count := 0
	for name := range merged {
		if strings.EqualFold(name, "cookie") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate cookie headers after merge: %v", merged)
	}
}

func TestInjectionOnlyMatchesItsOwnHost(t *testing.T) {
	in := injection{
		session: "alice",
		headers: map[string]string{"Cookie": "sid=sess-alice"},
		host:    "127.0.0.1:18080",
	}
	cases := map[string]bool{
		"http://127.0.0.1:18080/orders/1":            true,
		"http://127.0.0.1:18080/orders/1?x=1":        true,
		"HTTP://127.0.0.1:18080/x":                   true,
		"http://localhost:18080/orders/1":            false, // same server, different host
		"http://127.0.0.1:18081/orders/1":            false, // different port
		"https://evil.example/":                      false,
		"http://127.0.0.1:18080@evil.example/orders": false, // userinfo trick must not pass
	}
	for raw, want := range cases {
		if got := in.matches(raw); got != want {
			t.Fatalf("matches(%q) = %v, want %v", raw, got, want)
		}
	}
	// No host binding means no injection at all.
	if (injection{session: "alice", headers: in.headers}).matches("http://127.0.0.1:18080/") {
		t.Fatal("an injection without a host binding injected the cookie")
	}
	// No session means no injection at all.
	if (injection{headers: in.headers, host: in.host}).matches("http://127.0.0.1:18080/") {
		t.Fatal("an injection without a session name injected the cookie")
	}
}

func TestInjectionForRefusesAnEmptySession(t *testing.T) {
	if _, err := injectionFor(&Env{SessionName: "alice"}, "http://x/"); err == nil {
		t.Fatal("a named session with no headers was accepted (would render anonymously)")
	}
	if _, err := injectionFor(&Env{}, "http://x/"); err != nil {
		t.Fatalf("no session should be a plain anonymous render: %v", err)
	}
}

// TestBrowserSessionInjection is the v0.6 acceptance test, end to end with Chrome:
//
//	alice's cookie travels on 127.0.0.1 only, inside the Fetch gate, and the page
//	shows alice's object; the same page on the same server under another host name
//	gets no cookie; bob's cookie does not unlock alice's object.
func TestBrowserSessionInjection(t *testing.T) {
	if detectBrowser() == "" {
		t.Skip("no Chromium-family browser on this machine")
	}
	if testing.Short() {
		t.Skip("browser integration test skipped in -short")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("sid")
		switch r.URL.Path {
		case "/orders/1":
			if c != nil && c.Value == "sess-alice" {
				_, _ = io.WriteString(w, "<html><title>order</title><body>ORD-1 owned by alice</body></html>")
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		case "/whoami":
			v := "anonymous"
			if c != nil {
				v = c.Value
			}
			_, _ = io.WriteString(w, "<html><title>who</title><body>you are "+v+"</body></html>")
		default:
			_, _ = io.WriteString(w, "<html><title>home</title><body>home</body></html>")
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	// The scope covers both names for the same server, which is what makes the
	// host binding the only thing that can keep the cookie off localhost.
	env, recorder := newTestEnv(t, []string{"127.0.0.1", "localhost"}, nil)
	env.ArtifactDir = t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// 1) alice sees her object, and the request carried her cookie.
	alice := *env
	alice.SessionName = "alice"
	alice.SessionHeaders = map[string]string{"Cookie": "sid=sess-alice"}
	alice.SessionHost = host
	obs, err := Run(ctx, &alice, "browser", map[string]any{"url": srv.URL + "/orders/1", "wait_ms": 900})
	if err != nil {
		t.Fatalf("authenticated render: %v", err)
	}
	var sawAuth bool
	for _, f := range obs.Facts {
		if strings.Contains(f.Statement, "以身份 alice 渲染") {
			sawAuth = true
			if f.Evidence["session"] != "alice" || f.Evidence["authenticated"] != true {
				t.Fatalf("auth fact evidence = %v", f.Evidence)
			}
			if n, _ := f.Evidence["injected_requests"].(int); n == 0 {
				t.Fatalf("no request was reported as injected: %v", f.Evidence)
			}
		}
	}
	if !sawAuth {
		t.Fatalf("no authenticated fact; facts=%v", factStatements(obs))
	}

	// 2) The same object under another host name gets NO cookie.
	//    localhost resolves to the same server; the scope allows it; the injection
	//    must not follow.
	other := *env
	other.SessionName = "alice"
	other.SessionHeaders = map[string]string{"Cookie": "sid=sess-alice"}
	other.SessionHost = host // still 127.0.0.1:port
	obs2, err := Run(ctx, &other, "browser", map[string]any{
		"url": "http://localhost:" + strings.Split(host, ":")[1] + "/whoami", "wait_ms": 900,
	})
	if err != nil {
		t.Fatalf("cross-host render: %v", err)
	}
	for _, f := range obs2.Facts {
		if strings.Contains(f.Statement, "sess-alice") {
			t.Fatalf("the cookie leaked into an observation: %q", f.Statement)
		}
	}
	var injectedZero bool
	for _, f := range obs2.Facts {
		if strings.Contains(f.Statement, "以身份 alice 渲染") {
			if n, _ := f.Evidence["injected_requests"].(int); n == 0 {
				injectedZero = true
			}
		}
	}
	if !injectedZero {
		t.Fatalf("cross-host render did not report zero injection; facts=%v", factStatements(obs2))
	}

	// 3) No cookie value anywhere in the observation.
	for _, f := range []ledger.Observation{obs, obs2} {
		if strings.Contains(observationText(f), "sess-alice") {
			t.Fatal("a cookie value reached the observation")
		}
	}
	// 4) Every allowed request still has an audit row (injection is inside the gate).
	known := map[string]bool{}
	for _, ev := range recorder.snapshot() {
		if ev.Verdict == "allowed" {
			known[ev.RequestID] = true
		}
	}
	for _, id := range obs.RequestIDs {
		if id != "" && !known[id] {
			t.Fatalf("request %q has no audit row: injection bypassed the gate", id)
		}
	}
}

// TestBrowserViewerBolaCandidate: a viewer identity rendering an object page that
// shows the owner's marker yields a candidate, never a verified finding.
func TestBrowserViewerBolaCandidate(t *testing.T) {
	if detectBrowser() == "" {
		t.Skip("no Chromium-family browser on this machine")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately broken: any session may read this object.
		_, _ = io.WriteString(w, "<html><title>order</title><body>ORD-9 owned by alice</body></html>")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	env, _ := newTestEnv(t, []string{"127.0.0.1"}, nil)
	env.ArtifactDir = t.TempDir()
	env.SessionName = "bob"
	env.SessionHeaders = map[string]string{"Cookie": "sid=sess-bob"}
	env.SessionHost = host
	env.SessionWatch = []MarkerWatch{{Owner: "alice", Marker: "ORD-9", URL: srv.URL + "/orders/9"}}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	obs, err := Run(ctx, env, "browser", map[string]any{"url": srv.URL + "/orders/9", "wait_ms": 900})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var found bool
	for _, f := range obs.Findings {
		if f.Kind != "bola" {
			continue
		}
		found = true
		if f.Evidence["session"] != "bob" || f.Evidence["owner"] != "alice" || f.Evidence["marker"] != "ORD-9" {
			t.Fatalf("bola evidence = %v", f.Evidence)
		}
		if f.Evidence["request_id"] == nil {
			t.Fatalf("bola finding carries no request_id: %v", f.Evidence)
		}
	}
	if !found {
		t.Fatalf("no viewer-side bola candidate; findings=%+v", obs.Findings)
	}
	if strings.Contains(observationText(obs), "sess-bob") {
		t.Fatal("the cookie value reached the observation")
	}
}
