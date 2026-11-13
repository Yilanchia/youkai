package web

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// The browser capability: a real Chromium render with the guard still in the
// path.
//
// The problem a naive implementation has is decisive: the browser process opens
// its own sockets, so a page load is an egress the guard cannot see. youkai's
// answer is CDP network interception:
//
//	Fetch.enable(patterns *) -> every request pauses -> discipline.Guard decides
//	  allowed  -> Fetch.continueRequest  (and an audit row already exists)
//	  refused  -> Fetch.failRequest      (and a blocked audit row exists)
//
// That makes the browser a *client* of the guard rather than a way around it. The
// only unguarded socket in the process is the local CDP control channel, which
// dialWS refuses to open unless the endpoint is loopback.
//
// Note this is stricter than Fairy: Fairy lets rendering subresources through so
// pages look right. The GAPS requirement ("every in-page request") is the harder
// line, so every http(s) request is gated here, whatever its resource type. Pages
// with third-party CDNs will render incompletely until the operator adds those
// hosts to the passport - which is the correct outcome for a scoped engagement.

// browserWaitDefault is how long to let a page settle after load.
const browserWaitDefault = 800 * time.Millisecond

// maxGatedEvents bounds the evidence a single page can generate.
const maxBlockedEvidence = 20

type blockedRequest struct {
	URL       string `json:"url"`
	Method    string `json:"method"`
	Type      string `json:"resource_type,omitempty"`
	Reason    string `json:"reason"`
	RequestID string `json:"request_id,omitempty"`
}

// browserSession holds one launched browser and its gating state.
type browserSession struct {
	proc     *exec.Cmd
	profile  string
	client   *cdpClient
	pageSess string

	mu       sync.Mutex
	allowed  []string // request ids that were authorised
	blocked  []blockedRequest
	requests []browserRequest
}

type browserRequest struct {
	URL     string `json:"url"`
	Method  string `json:"method"`
	Type    string `json:"type"`
	Status  int    `json:"status"`
	Failed  bool   `json:"failed"`
	Allowed bool   `json:"allowed"`
	ReqID   string `json:"request_id,omitempty"`
}

func runBrowser(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	g, err := guardOf(env)
	if err != nil {
		return ledger.Observation{}, err
	}

	exe := detectBrowser()
	if exe == "" {
		return ledger.Observation{}, fmt.Errorf(
			"%w: 本机未找到 Chrome/Edge(检查 PATH 与常见安装目录);browser 需要 CDP 渲染后端", ErrUnavailable)
	}

	// Fail fast on a navigation target the passport does not cover. No browser is
	// launched, but the attempt is recorded so the refusal is visible.
	if _, cherr := g.Scope().Check(rawURL); cherr != nil {
		g.Refuse(ctx, "GET", rawURL, "browser", "navigation target rejected before launch: "+cherr.Error(), nil)
		return ledger.Observation{}, fmt.Errorf("web: browser: %w", cherr)
	}

	profileRoot := env.ArtifactDir
	if profileRoot == "" {
		profileRoot = filepath.Join(os.TempDir(), "youkai-browser")
	}
	if err := os.MkdirAll(profileRoot, 0o700); err != nil {
		return ledger.Observation{}, fmt.Errorf("web: browser: artifact dir: %w", err)
	}

	sess, err := launchBrowser(ctx, exe, profileRoot)
	if err != nil {
		return ledger.Observation{}, err
	}
	defer sess.Close()

	if err := sess.attach(ctx); err != nil {
		return ledger.Observation{}, err
	}
	if err := sess.enableGating(ctx, g); err != nil {
		return ledger.Observation{}, err
	}

	waitMs := time.Duration(argInt(args, "wait_ms", 800)) * time.Millisecond
	if waitMs <= 0 {
		waitMs = browserWaitDefault
	}
	if _, err := sess.client.Send(ctx, "Page.navigate", map[string]any{"url": rawURL}, sess.pageSess); err != nil {
		return ledger.Observation{}, fmt.Errorf("web: browser: navigate: %w", err)
	}
	sess.client.waitFor(ctx, "Page.loadEventFired", 20*time.Second)
	select {
	case <-time.After(waitMs):
	case <-ctx.Done():
		return ledger.Observation{}, ctx.Err()
	}

	obs := ledger.Observation{}
	snapshot, snapErr := sess.snapshot(ctx)
	if snapErr != nil {
		obs.Facts = append(obs.Facts, ledger.FactSeed{
			Statement: "浏览器渲染完成,但 DOM 快照失败:" + snapErr.Error(),
			Evidence:  map[string]any{"url": rawURL},
			Tags:      []string{"browser", "degraded"},
		})
	}

	sess.mu.Lock()
	allowed := append([]string(nil), sess.allowed...)
	blocked := append([]blockedRequest(nil), sess.blocked...)
	requests := append([]browserRequest(nil), sess.requests...)
	sess.mu.Unlock()

	firstReq := ""
	if len(allowed) > 0 {
		firstReq = allowed[0]
	}
	evidence := func() map[string]any {
		if firstReq == "" {
			return map[string]any{"purpose": "browser", "gated_requests": len(allowed)}
		}
		return map[string]any{"request_id": firstReq, "gated_requests": len(allowed)}
	}

	title, finalURL := rawURL, rawURL
	if snapshot != nil {
		title = snapshot.Title
		if snapshot.URL != "" {
			finalURL = snapshot.URL
		}
	}
	obs.Facts = append(obs.Facts, ledger.FactSeed{
		Statement: fmt.Sprintf("浏览器渲染:%s (%s)", fallback(title, "(无标题)"), finalURL),
		Evidence:  evidence(),
		Tags:      []string{"browser", "render"},
		Anchors:   []string{"surface:" + finalURL},
	})
	obs.Assets = append(obs.Assets, ledger.AssetSeed{
		Kind: "surface", Value: "surface:" + finalURL,
		Props: map[string]any{"url": finalURL, "title": title, "rendered": true},
	})

	if snapshot != nil {
		for _, link := range snapshot.Links {
			obs.Facts = append(obs.Facts, ledger.FactSeed{
				Statement: "页面链接:" + link,
				Evidence:  map[string]any{"url": link, "request_id": firstReq},
				Tags:      []string{"browser", "link"},
			})
		}
		for _, f := range snapshot.Forms {
			obs.Facts = append(obs.Facts, ledger.FactSeed{
				Statement: fmt.Sprintf("页面表单:%s %s fields=[%s]", strings.ToUpper(f.Method), f.Action, strings.Join(f.Fields, ",")),
				Evidence:  map[string]any{"action": f.Action, "method": f.Method, "request_id": firstReq},
				Tags:      []string{"browser", "form"},
			})
			obs.Assets = append(obs.Assets, ledger.AssetSeed{
				Kind: "endpoint", Value: "endpoint:" + f.Action,
				Props: map[string]any{"method": strings.ToUpper(f.Method), "source": "dom-form"},
			})
		}
	}

	// XHR / fetch endpoints observed by the network layer.
	xhr := 0
	for _, r := range requests {
		if r.Type != "XHR" && r.Type != "Fetch" {
			continue
		}
		xhr++
		if xhr <= 50 {
			obs.Facts = append(obs.Facts, ledger.FactSeed{
				Statement: fmt.Sprintf("页面 XHR:%s %s → %d", r.Method, r.URL, r.Status),
				Evidence:  map[string]any{"url": r.URL, "status": r.Status, "request_id": r.ReqID},
				Tags:      []string{"browser", "xhr"},
			})
			obs.Assets = append(obs.Assets, ledger.AssetSeed{
				Kind: "endpoint", Value: "endpoint:" + r.URL,
				Props: map[string]any{"method": r.Method, "status": r.Status, "source": "browser-xhr"},
			})
		}
	}
	if xhr > 0 {
		obs.Facts = append(obs.Facts, ledger.FactSeed{
			Statement: fmt.Sprintf("页面动态请求 XHR/Fetch:%d 条", xhr),
			Evidence:  evidence(),
			Tags:      []string{"browser", "xhr", "count"},
		})
	}

	// Blocked requests are evidence: the gate did its job, and the operator can
	// see what the page tried to reach.
	if len(blocked) > 0 {
		for i, b := range blocked {
			if i >= maxBlockedEvidence {
				break
			}
			obs.Facts = append(obs.Facts, ledger.FactSeed{
				Statement: fmt.Sprintf("越界请求被拦断:%s %s (%s)", b.Method, b.URL, b.Reason),
				Evidence:  map[string]any{"url": b.URL, "method": b.Method, "reason": b.Reason, "request_id": b.RequestID},
				Tags:      []string{"browser", "scope-blocked"},
			})
		}
		obs.Findings = append(obs.Findings, ledger.FindingSeed{
			Title:    fmt.Sprintf("页面尝试访问 %d 个越界目标(已被拦断)", len(blocked)),
			Severity: "info",
			Kind:     "scope-blocked",
			Where:    finalURL,
			Detail:   "这些请求在浏览器网络层由 discipline.Guard 拦断并记审计;youkai 没有放出任何越界字节。",
			Evidence: evidence(),
			Tags:     []string{"browser", "scope"},
			Anchors:  []string{"surface:" + finalURL},
		})
		for _, b := range blocked {
			obs.RequestIDs = append(obs.RequestIDs, b.RequestID)
		}
	}

	if snapshot != nil && len(snapshot.ConsoleErrors) > 0 {
		for _, ce := range snapshot.ConsoleErrors {
			obs.Facts = append(obs.Facts, ledger.FactSeed{
				Statement: "页面控制台异常:" + ce,
				Evidence:  map[string]any{"url": finalURL, "request_id": firstReq},
				Tags:      []string{"browser", "console"},
			})
		}
	}

	if shot, shotErr := sess.screenshot(ctx); shotErr == nil && len(shot) > 0 {
		path := filepath.Join(profileRoot, "browser", fmt.Sprintf("shot-%d.png", time.Now().UnixNano()))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
			if writeErr := os.WriteFile(path, shot, 0o600); writeErr == nil {
				obs.Facts = append(obs.Facts, ledger.FactSeed{
					Statement: fmt.Sprintf("页面截图:%s (%d bytes)", path, len(shot)),
					Evidence:  map[string]any{"path": path, "request_id": firstReq},
					Tags:      []string{"browser", "screenshot"},
				})
			}
		}
	}

	obs.RequestIDs = append(obs.RequestIDs, allowed...)
	obs.Summary = fmt.Sprintf("browser: %q, %d gated, %d blocked, %d xhr",
		fallback(title, "(no title)"), len(allowed), len(blocked), xhr)
	return obs, nil
}

// ---- launch / attach -------------------------------------------------------

// launchBrowser starts headless Chromium and returns once the DevTools endpoint
// is known.
func launchBrowser(ctx context.Context, exe, profileRoot string) (*browserSession, error) {
	profile := filepath.Join(profileRoot, "browser", fmt.Sprintf("profile-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return nil, fmt.Errorf("web: browser: create profile: %w", err)
	}
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-sync",
		"--disable-extensions",
		"--disable-default-apps",
		"--mute-audio",
		"--hide-scrollbars",
		"--window-size=1280,800",
		"--user-data-dir=" + profile,
		"--remote-debugging-port=0",
		"about:blank",
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = profile
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("web: browser: stderr pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("web: browser: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: 启动浏览器失败:%v", ErrUnavailable, err)
	}

	wsURL, err := readDevToolsURL(ctx, stderr, stdout)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	client, err := dialCDP(ctx, wsURL)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("web: browser: %w", err)
	}
	return &browserSession{proc: cmd, profile: profile, client: client}, nil
}

var devtoolsRe = regexp.MustCompile(`DevTools listening on (ws://\S+)`)

// readDevToolsURL scans the browser's output for the DevTools endpoint.
func readDevToolsURL(ctx context.Context, readers ...io.Reader) (string, error) {
	type result struct {
		url string
		err error
	}
	out := make(chan result, len(readers))
	for _, r := range readers {
		go func(rd io.Reader) {
			sc := bufio.NewScanner(rd)
			sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
			for sc.Scan() {
				if m := devtoolsRe.FindStringSubmatch(sc.Text()); m != nil {
					out <- result{url: m[1]}
					return
				}
			}
			out <- result{err: fmt.Errorf("浏览器未打印 DevTools 端点(可能被策略禁用)")}
		}(r)
	}
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for i := 0; i < len(readers); i++ {
		select {
		case res := <-out:
			if res.url != "" {
				return res.url, nil
			}
		case <-deadline.C:
			return "", fmt.Errorf("浏览器启动超时(20s)")
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return "", fmt.Errorf("浏览器未打印 DevTools 端点")
}

// attach creates a page target and attaches to it in flat mode.
func (s *browserSession) attach(ctx context.Context) error {
	created, err := s.client.Send(ctx, "Target.createTarget", map[string]any{"url": "about:blank"}, "")
	if err != nil {
		return fmt.Errorf("web: browser: create target: %w", err)
	}
	var createdRes struct {
		TargetID string `json:"targetId"`
	}
	if err := json.Unmarshal(created, &createdRes); err != nil || createdRes.TargetID == "" {
		return fmt.Errorf("web: browser: create target returned no id")
	}
	attached, err := s.client.Send(ctx, "Target.attachToTarget", map[string]any{
		"targetId": createdRes.TargetID, "flatten": true,
	}, "")
	if err != nil {
		return fmt.Errorf("web: browser: attach: %w", err)
	}
	var attachRes struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(attached, &attachRes); err != nil || attachRes.SessionID == "" {
		return fmt.Errorf("web: browser: attach returned no session id")
	}
	s.pageSess = attachRes.SessionID
	return nil
}

// enableGating turns on the domains and installs the per-request gate.
func (s *browserSession) enableGating(ctx context.Context, g *discipline.Guard) error {
	sid := s.pageSess
	for _, domain := range []string{"Page.enable", "Runtime.enable", "Network.enable"} {
		if _, err := s.client.Send(ctx, domain, nil, sid); err != nil {
			return fmt.Errorf("web: browser: %s: %w", domain, err)
		}
	}
	// Patterns: every request, at the Request stage.
	if _, err := s.client.Send(ctx, "Fetch.enable", map[string]any{
		"patterns": []map[string]any{{"urlPattern": "*", "requestStage": "Request"}},
	}, sid); err != nil {
		return fmt.Errorf("web: browser: Fetch.enable: %w", err)
	}
	s.installFetchGate(g, sid)

	// Child targets (popups, out-of-process iframes) must be gated too, or a page
	// could open an unguarded frame. Auto-attach waits for the debugger, so the
	// first request of a new target is already intercepted.
	s.client.On("Target.attachedToTarget", func(childSess string, params json.RawMessage) {
		if childSess == "" || childSess == sid {
			return
		}
		bg := context.Background()
		for _, domain := range []string{"Page.enable", "Runtime.enable", "Network.enable"} {
			_, _ = s.client.Send(bg, domain, nil, childSess)
		}
		_, _ = s.client.Send(bg, "Fetch.enable", map[string]any{
			"patterns": []map[string]any{{"urlPattern": "*", "requestStage": "Request"}},
		}, childSess)
		s.installFetchGate(g, childSess)
		_, _ = s.client.Send(bg, "Runtime.runIfWaitingForDebugger", nil, childSess)
	})
	if _, err := s.client.Send(ctx, "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
	}, ""); err != nil {
		// Fail closed. Without auto-attach a child target (popup, out-of-process
		// iframe, worker) gets its own CDP session whose requests never reach this
		// session's Fetch gate - an unguarded egress. "No unguarded request" is an
		// absolute invariant, not a best effort, so refuse to render at all rather
		// than render with a gap the operator would only notice after the fact.
		return fmt.Errorf("web: browser: Target.setAutoAttach failed (%w); refusing to render without child-target gating", err)
	}
	return nil
}

// installFetchGate wires Fetch.requestPaused to the guard for one session.
func (s *browserSession) installFetchGate(g *discipline.Guard, sid string) {
	s.client.On("Fetch.requestPaused", func(sessionID string, params json.RawMessage) {
		if sessionID != sid {
			return
		}
		var p struct {
			RequestID    string `json:"requestId"`
			ResourceType string `json:"resourceType"`
			Request      struct {
				URL    string `json:"url"`
				Method string `json:"method"`
			} `json:"request"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.RequestID == "" {
			return
		}
		rawURL := p.Request.URL
		method := p.Request.Method
		if method == "" {
			method = "GET"
		}

		// Only http(s) is a target request. data:/blob:/about: cannot leave the
		// process, so continuing them is not an egress.
		if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
			s.continueRequest(sid, p.RequestID)
			return
		}

		bg := context.Background()
		auth, err := g.Authorize(bg, method, rawURL, "browser", map[string]any{
			"resource_type": p.ResourceType, "cdp_session": sid,
		})
		if err != nil {
			s.recordBlocked(blockedRequest{
				URL: rawURL, Method: method, Type: p.ResourceType, Reason: err.Error(),
			})
			_, _ = s.client.Send(bg, "Fetch.failRequest", map[string]any{
				"requestId": p.RequestID, "errorReason": "BlockedByClient",
			}, sid)
			return
		}
		s.mu.Lock()
		s.allowed = append(s.allowed, auth.RequestID)
		s.requests = append(s.requests, browserRequest{
			URL: rawURL, Method: method, Type: p.ResourceType, Allowed: true, ReqID: auth.RequestID,
		})
		s.mu.Unlock()
		s.continueRequest(sid, p.RequestID)
	})

	// Network events give the XHR list its status codes.
	s.client.On("Network.requestWillBeSent", func(sessionID string, params json.RawMessage) {
		if sessionID != sid {
			return
		}
		var p struct {
			Type    string `json:"type"`
			Request struct {
				URL    string `json:"url"`
				Method string `json:"method"`
			} `json:"request"`
		}
		if json.Unmarshal(params, &p) != nil {
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, browserRequest{URL: p.Request.URL, Method: p.Request.Method, Type: p.Type})
		s.mu.Unlock()
	})
	s.client.On("Network.responseReceived", func(sessionID string, params json.RawMessage) {
		if sessionID != sid {
			return
		}
		var p struct {
			Response struct {
				URL    string `json:"url"`
				Status int    `json:"status"`
			} `json:"response"`
		}
		if json.Unmarshal(params, &p) != nil {
			return
		}
		s.mu.Lock()
		for i := len(s.requests) - 1; i >= 0; i-- {
			if s.requests[i].URL == p.Response.URL && s.requests[i].Status == 0 {
				s.requests[i].Status = p.Response.Status
				break
			}
		}
		s.mu.Unlock()
	})
}

func (s *browserSession) continueRequest(sid, requestID string) {
	bg := context.Background()
	_, _ = s.client.Send(bg, "Fetch.continueRequest", map[string]any{"requestId": requestID}, sid)
}

func (s *browserSession) recordBlocked(b blockedRequest) {
	s.mu.Lock()
	if len(s.blocked) < 200 {
		s.blocked = append(s.blocked, b)
	}
	s.mu.Unlock()
}

// ---- snapshot --------------------------------------------------------------

type domSnapshot struct {
	Title         string    `json:"title"`
	URL           string    `json:"url"`
	Links         []string  `json:"links"`
	Forms         []domForm `json:"forms"`
	ConsoleErrors []string  `json:"-"`
}

type domForm struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Fields []string `json:"fields"`
}

const snapshotJS = `(function(){
  try {
    var links = Array.prototype.slice.call(document.querySelectorAll('a[href]'))
      .slice(0, 200).map(function(a){ return a.href; })
      .filter(function(h){ return /^https?:/i.test(h); });
    var forms = Array.prototype.slice.call(document.forms).slice(0, 20).map(function(f){
      var fields = Array.prototype.slice.call(f.elements).slice(0, 20)
        .map(function(e){ return e.name || e.id; }).filter(Boolean);
      return { action: f.action, method: (f.method||'GET').toUpperCase(), fields: fields };
    });
    return JSON.stringify({ title: document.title, url: location.href, links: links, forms: forms });
  } catch (e) { return JSON.stringify({ title: '', url: location.href, links: [], forms: [], error: String(e) }); }
})()`

// snapshot reads the rendered DOM.
func (s *browserSession) snapshot(ctx context.Context) (*domSnapshot, error) {
	raw, err := s.client.Send(ctx, "Runtime.evaluate", map[string]any{
		"expression":    snapshotJS,
		"returnByValue": true,
		"awaitPromise":  false,
	}, s.pageSess)
	if err != nil {
		return nil, err
	}
	var outer struct {
		Result struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"result"`
		ExceptionDetails json.RawMessage `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil {
		return nil, err
	}
	if len(outer.ExceptionDetails) > 0 {
		return nil, fmt.Errorf("页面脚本异常")
	}
	var snap domSnapshot
	if err := json.Unmarshal([]byte(outer.Result.Value), &snap); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &snap, nil
}

// screenshot captures a PNG of the viewport.
func (s *browserSession) screenshot(ctx context.Context) ([]byte, error) {
	raw, err := s.client.Send(ctx, "Page.captureScreenshot", map[string]any{"format": "png"}, s.pageSess)
	if err != nil {
		return nil, err
	}
	var res struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	if res.Data == "" {
		return nil, fmt.Errorf("empty screenshot")
	}
	return base64.StdEncoding.DecodeString(res.Data)
}

// Close kills the browser and removes the throwaway profile.
func (s *browserSession) Close() {
	if s.client != nil {
		s.client.Close()
	}
	if s.proc != nil && s.proc.Process != nil {
		_ = s.proc.Process.Kill()
		_, _ = s.proc.Process.Wait()
	}
	// Chrome may still hold files on Windows; a failed cleanup is not an error.
	_ = os.RemoveAll(s.profile)
}

func fallback(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// isHTTPURL reports whether a string is an http(s) URL.
func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

// detectBrowser looks for a Chromium-family executable without launching it.
//
// A browser that is not installed is a degradation, not a failure to fake: the
// capability returns ErrUnavailable with this reason and `doctor` shows it red.
func detectBrowser() string {
	if override := strings.TrimSpace(os.Getenv("YOUKAI_BROWSER")); override != "" {
		if info, err := os.Stat(override); err == nil && !info.IsDir() {
			return override
		}
		return ""
	}
	names := []string{
		"chrome", "chrome.exe",
		"google-chrome", "google-chrome-stable",
		"chromium", "chromium-browser",
		"msedge", "msedge.exe", "microsoft-edge",
	}
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil && p != "" {
			return p
		}
	}
	roots := []string{
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("LocalAppData"),
	}
	relatives := []string{
		filepath.Join("Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join("Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join("Chromium", "Application", "chrome.exe"),
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		for _, rel := range relatives {
			candidate := filepath.Join(root, rel)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
	}
	return ""
}
