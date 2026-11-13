package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// ErrNeedsHuman marks a step youkai refuses to do on its own: a CAPTCHA, an SMS
// code, a phone number. The caller surfaces it as "a human must continue", never
// as a failure to retry.
var ErrNeedsHuman = errors.New("accounts: 需要人工处理这一步")

// Env is the account layer's environment. Guard is the engagement's guard; the
// service clones it per identity so cookie jars cannot bleed.
type Env struct {
	Guard        *discipline.Guard
	Store        *ledger.Store
	EngagementID int64
	Engagement   string
	ManifestPath string
	SessionDir   string
}

// Service is one engagement's account layer.
type Service struct {
	Env      Env
	Manifest *Manifest
	Sessions *SessionStore
}

// Open loads the manifest and session store for an environment.
//
// A missing manifest is not an error: the UI still needs to render "no identities
// configured yet". A malformed one is an error - silently provisioning from a
// half-parsed manifest would be worse than refusing.
func Open(env Env) (*Service, error) {
	if env.Guard == nil {
		return nil, errors.New("accounts: 需要 discipline.Guard(无 guard 不动作)")
	}
	manifestPath := env.ManifestPath
	if strings.TrimSpace(manifestPath) == "" {
		manifestPath = DefaultPath
	}
	sessions, err := NewSessionStore(env.SessionDir)
	if err != nil {
		return nil, err
	}
	m, err := Loaded(manifestPath)
	if err != nil {
		return nil, err
	}
	return &Service{Env: env, Manifest: m, Sessions: sessions}, nil
}

// ---- show ------------------------------------------------------------------

// ProvisionedAccount is one identity that logged in.
type ProvisionedAccount struct {
	Name         string `json:"name"`
	Role         string `json:"role"`
	SessionReady bool   `json:"session_ready"`
	Status       int    `json:"status"`
	RequestID    string `json:"request_id"`
	Enc          string `json:"enc"`
}

// FailedAccount is one identity that did not.
type FailedAccount struct {
	Name  string `json:"name"`
	Role  string `json:"role"`
	Error string `json:"error"`
}

// ProvisionReport is what an operator sees after provisioning.
type ProvisionReport struct {
	Provisioned []ProvisionedAccount `json:"provisioned"`
	Failed      []FailedAccount      `json:"failed"`
	Warnings    []string             `json:"warnings,omitempty"`
	Note        string               `json:"note"`
}

// Show renders the redacted account view.
//
// A missing manifest is a normal state (nobody configured identities yet), not an
// error: the UI renders an empty table plus a warning telling the operator what to
// write. Only a malformed manifest refuses.
func (s *Service) Show() (Show, error) {
	if s.Manifest == nil {
		return Show{
			Path:       DefaultPath,
			Schema:     Schema,
			SessionDir: s.Sessions.Dir,
			Warnings: []string{
				"没有账号清单(" + DefaultPath + ");先由授权人写一份 " + Schema +
					",密码走 password_env 环境变量",
			},
		}, nil
	}
	ready := map[string]bool{}
	if list, err := s.Sessions.List(); err == nil {
		for _, info := range list {
			ready[info.Name] = true
		}
	}
	out := Show{
		Path:       s.Manifest.Path,
		Schema:     s.Manifest.Schema,
		BaseURL:    s.Manifest.BaseURL,
		Warnings:   s.Manifest.Warnings,
		SessionDir: s.Sessions.Dir,
		BolaPairs:  s.Manifest.BolaPairs(),
	}
	for _, a := range s.Manifest.Accounts {
		markers := make([]string, 0, len(a.Owns))
		for _, own := range a.Owns {
			markers = append(markers, own.Marker)
		}
		out.Accounts = append(out.Accounts, ShowAccount{
			Name: a.Name, Role: a.Role, Owns: markers, SessionReady: ready[a.Name],
		})
	}
	if !s.Sessions.Keyed {
		out.Warnings = append(out.Warnings,
			"未设置 "+EnvSessionKey+":会话以 base64 存放(等同明文)。真实目标请设置密钥。")
	}
	return out, nil
}

// ---- provision -------------------------------------------------------------

// Provision logs each selected identity in exactly once, stores the session, and
// returns the facts that record it.
//
// Discipline inherited from Fairy: one attempt per account, no retry, no
// dictionary. A failed login is reported, not retried, and nothing about the
// credential is copied into the observation.
func (s *Service) Provision(ctx context.Context, only []string) (ledger.Observation, ProvisionReport, error) {
	rep := ProvisionReport{Note: "只登录一次,不重试、不爆破;会话值不在此输出。"}
	if s.Manifest == nil {
		return ledger.Observation{}, rep, fmt.Errorf("accounts: 没有账号清单(%s)", DefaultPath)
	}
	selected, err := s.selectAccounts(only)
	if err != nil {
		return ledger.Observation{}, rep, err
	}
	rep.Warnings = append(rep.Warnings, s.Manifest.Warnings...)

	var obs ledger.Observation
	for _, a := range selected {
		password, source, err := a.Login.Credential()
		if err != nil {
			rep.Failed = append(rep.Failed, FailedAccount{Name: a.Name, Role: a.Role, Error: err.Error()})
			continue
		}

		method := strings.ToUpper(strings.TrimSpace(a.Login.Method))
		if method == "" {
			method = "POST"
		}
		fields := map[string]string{}
		for k, v := range a.Login.Fields {
			fields[k] = v
		}
		fields["password"] = password

		headers := map[string]string{}
		var body []byte
		if a.Login.JSON {
			encoded, encErr := json.Marshal(fields)
			if encErr != nil {
				rep.Failed = append(rep.Failed, FailedAccount{Name: a.Name, Role: a.Role, Error: encErr.Error()})
				continue
			}
			body = encoded
			headers["Content-Type"] = "application/json"
		} else {
			form := url.Values{}
			for k, v := range fields {
				form.Set(k, v)
			}
			body = []byte(form.Encode())
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		}

		// One clone per identity: its own cookie jar, shared budget.
		g := s.Env.Guard.Clone()
		res, doErr := g.Do(ctx, discipline.Request{
			Method:          method,
			URL:             a.Login.URL,
			Headers:         headers,
			Body:            body,
			Purpose:         "accounts_provision",
			FollowRedirects: false,
		})
		if doErr != nil {
			rep.Failed = append(rep.Failed, FailedAccount{Name: a.Name, Role: a.Role, Error: doErr.Error()})
			continue
		}

		sessionHeaders, sessErr := s.captureSession(g, a, res)
		if sessErr != nil {
			rep.Failed = append(rep.Failed, FailedAccount{Name: a.Name, Role: a.Role, Error: sessErr.Error()})
			continue
		}
		info, saveErr := s.Sessions.Save(a.Name, sessionHeaders, "provisioned by youkai")
		if saveErr != nil {
			rep.Failed = append(rep.Failed, FailedAccount{Name: a.Name, Role: a.Role, Error: saveErr.Error()})
			continue
		}

		rep.Provisioned = append(rep.Provisioned, ProvisionedAccount{
			Name: a.Name, Role: a.Role, SessionReady: true,
			Status: res.Status, RequestID: res.RequestID, Enc: info.Enc,
		})

		obs.Assets = append(obs.Assets, ledger.AssetSeed{
			Kind: "account", Value: "account:" + a.Name,
			Props: map[string]any{"role": a.Role, "session_ready": true, "credential_source": source},
		})
		obs.Facts = append(obs.Facts, ledger.FactSeed{
			Statement: fmt.Sprintf("账号 %s 已登录 (%s)", a.Name, a.Role),
			Evidence: map[string]any{
				"request_id": res.RequestID, "status": res.Status,
				"session": a.Name, "session_fingerprint": Fingerprint(sessionHeaders),
			},
			Tags:    []string{"account", a.Role},
			Anchors: []string{"account:" + a.Name},
		})
		for _, own := range a.Owns {
			u := s.absoluteURL(a, own.URL)
			obs.Facts = append(obs.Facts, ledger.FactSeed{
				Statement: fmt.Sprintf("%s 拥有对象 %s (%s)", a.Name, own.Marker, u),
				Evidence: map[string]any{
					"url": u, "marker": own.Marker, "note": own.Note,
					"request_id": res.RequestID,
				},
				Tags:    []string{"ownership", a.Role},
				Anchors: []string{"account:" + a.Name},
			})
		}
		obs.RequestIDs = append(obs.RequestIDs, res.RequestID)
	}
	obs.Summary = fmt.Sprintf("provision %d/%d", len(rep.Provisioned), len(rep.Provisioned)+len(rep.Failed))
	if len(rep.Provisioned) == 0 && len(rep.Failed) > 0 {
		// Nothing worked: that is a failure, not a partial success. The report is
		// still returned so the operator sees every reason.
		return obs, rep, fmt.Errorf("accounts: 没有账号登录成功(%d 个失败)", len(rep.Failed))
	}
	return obs, rep, nil
}

// captureSession turns a login response into request headers.
//
// Cookies come from the guard's jar (the sanitised response headers only carry
// names, which is the whole point). A JSON login that returns a token gets an
// Authorization header instead.
func (s *Service) captureSession(g *discipline.Guard, a Account, res *discipline.Response) (map[string]string, error) {
	headers := map[string]string{}
	if cookie := discipline.CookieHeader(g.SessionCookies(a.Login.URL)); cookie != "" {
		headers["Cookie"] = cookie
	}
	if field := strings.TrimSpace(a.Login.TokenField); field != "" {
		if tok := extractToken(res.Text(), field); tok != "" {
			headers["Authorization"] = "Bearer " + tok
		}
	}
	redirected := res.Status >= 300 && res.Status < 400
	if len(headers) == 0 {
		return nil, fmt.Errorf("登录未产生会话(HTTP %d,无 Set-Cookie/令牌);确认 login.url 与字段名,不重试", res.Status)
	}
	if !redirected && res.Status >= 400 {
		return nil, fmt.Errorf("登录失败(HTTP %d)", res.Status)
	}
	return headers, nil
}

func extractToken(body, field string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		return v
	}
	if data, ok := m["data"].(map[string]any); ok {
		if v, ok := data[field].(string); ok {
			return v
		}
	}
	return ""
}

// ---- seeding ---------------------------------------------------------------

// SeededObject is one object an identity created for itself.
type SeededObject struct {
	Account   string `json:"account"`
	Marker    string `json:"marker"`
	URL       string `json:"url"`
	RequestID string `json:"request_id"`
	Status    int    `json:"status"`
}

// SeedReport is what the operator sees.
type SeedReport struct {
	Seeded    []SeededObject  `json:"seeded"`
	Failed    []FailedAccount `json:"failed"`
	BolaPairs []Pair          `json:"bola_pairs"`
	Note      string          `json:"note"`
}

// Seed creates one minimal object per identity, for ownership ground truth.
//
// Three gates before a single byte is written: the passport must set
// allow_object_seeding, must authorise POST, and the caller must pass confirm.
// One object per account; nothing is modified, deleted, or created in bulk. The
// ownership is recorded as a fact, not written back into the manifest.
func (s *Service) Seed(ctx context.Context, confirm bool, only []string) (ledger.Observation, SeedReport, error) {
	rep := SeedReport{Note: "每个账号只创建一个最小对象;不删、不改、不批量;seeded 归属只落账本事实。"}
	if s.Manifest == nil {
		return ledger.Observation{}, rep, fmt.Errorf("accounts: 没有账号清单(%s)", DefaultPath)
	}
	scope := s.Env.Guard.Scope()
	if scope == nil || !scope.AllowObjectSeeding {
		return ledger.Observation{}, rep, fmt.Errorf(
			"accounts: 对象播种未授权:需要 scope.allow_object_seeding=true(这是档 2 写操作)")
	}
	if !scope.MethodAllowed("POST") {
		return ledger.Observation{}, rep, fmt.Errorf(
			"accounts: 对象播种需要 scope.methods 包含 POST(当前 %v)", scope.Methods)
	}
	if !confirm {
		return ledger.Observation{}, rep, fmt.Errorf(
			"accounts: 对象播种需要 confirm=true:它会创建最小测试对象,必须显式确认")
	}

	selected, err := s.selectAccounts(only)
	if err != nil {
		return ledger.Observation{}, rep, err
	}
	var obs ledger.Observation
	for _, a := range selected {
		if a.Seed == nil || strings.TrimSpace(a.Seed.Create.URL) == "" {
			continue
		}
		sess, sessErr := s.Sessions.Load(a.Name)
		if sessErr != nil {
			rep.Failed = append(rep.Failed, FailedAccount{Name: a.Name, Role: a.Role, Error: sessErr.Error()})
			continue
		}
		createURL := s.absoluteURL(a, a.Seed.Create.URL)
		fields := map[string]string{}
		for k, v := range a.Seed.Create.Fields {
			fields[k] = v
		}
		headers := map[string]string{}
		for k, v := range sess.Headers {
			headers[k] = v
		}
		var body []byte
		if a.Seed.Create.JSON {
			encoded, encErr := json.Marshal(fields)
			if encErr != nil {
				rep.Failed = append(rep.Failed, FailedAccount{Name: a.Name, Role: a.Role, Error: encErr.Error()})
				continue
			}
			body = encoded
			headers["Content-Type"] = "application/json"
		} else {
			form := url.Values{}
			for k, v := range fields {
				form.Set(k, v)
			}
			body = []byte(form.Encode())
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		}

		g := s.Env.Guard.Clone()
		res, doErr := g.Do(ctx, discipline.Request{
			Method: "POST", URL: createURL, Headers: headers, Body: body,
			Purpose: "accounts_seed", FollowRedirects: false,
		})
		if doErr != nil {
			rep.Failed = append(rep.Failed, FailedAccount{Name: a.Name, Role: a.Role, Error: doErr.Error()})
			continue
		}
		if res.Status < 200 || res.Status >= 300 {
			rep.Failed = append(rep.Failed, FailedAccount{
				Name: a.Name, Role: a.Role, Error: fmt.Sprintf("创建对象返回 HTTP %d", res.Status)})
			continue
		}
		value := extractBySpec(res.Text(), a.Seed.Extract)
		if value == "" {
			rep.Failed = append(rep.Failed, FailedAccount{
				Name: a.Name, Role: a.Role, Error: "无法从创建响应提取对象 id(检查 seed.extract)"})
			continue
		}
		marker := value
		if a.Seed.MarkerPath != "" {
			if v := extractBySpec(res.Text(), SeedExtract{From: "json", Path: a.Seed.MarkerPath}); v != "" {
				marker = v
			}
		} else if a.Seed.Marker != "" {
			marker = a.Seed.Marker
		}
		itemTemplate := a.Seed.ItemURL
		if itemTemplate == "" {
			itemTemplate = strings.TrimRight(createURL, "/") + "/{id}"
		}
		itemURL := s.absoluteURL(a, strings.ReplaceAll(itemTemplate, "{id}", value))

		rep.Seeded = append(rep.Seeded, SeededObject{
			Account: a.Name, Marker: marker, URL: itemURL,
			RequestID: res.RequestID, Status: res.Status,
		})
		obs.Facts = append(obs.Facts, ledger.FactSeed{
			Statement: fmt.Sprintf("%s 自建对象 %s (%s)", a.Name, marker, itemURL),
			Evidence: map[string]any{
				"request_id": res.RequestID, "status": res.Status,
				"url": itemURL, "marker": marker, "seeded": true,
			},
			Tags:    []string{"ownership", "seeded", a.Role},
			Anchors: []string{"account:" + a.Name},
		})
		obs.RequestIDs = append(obs.RequestIDs, res.RequestID)
	}

	// Recompute the pairs including seeded ownership, so the operator sees the
	// comparisons this unlocks.
	rep.BolaPairs = s.Manifest.BolaPairs()
	for _, seeded := range rep.Seeded {
		for _, viewer := range s.Manifest.Accounts {
			if viewer.Name == seeded.Account {
				continue
			}
			rep.BolaPairs = append(rep.BolaPairs, Pair{
				Owner: seeded.Account, Viewer: viewer.Name,
				Marker: seeded.Marker, URL: seeded.URL, Action: "compare",
				Args: map[string]any{
					"url": seeded.URL, "session_a": seeded.Account,
					"session_b": viewer.Name, "marker": seeded.Marker,
				},
				Note: fmt.Sprintf("BOLA(seeded): %s 的对象 %s,换 %s 读取", seeded.Account, seeded.Marker, viewer.Name),
			})
		}
	}
	obs.Summary = fmt.Sprintf("seeded %d/%d objects", len(rep.Seeded), len(rep.Seeded)+len(rep.Failed))
	return obs, rep, nil
}

// ---- registration ----------------------------------------------------------

// RegisterReport is what the operator sees for a self-registration attempt.
type RegisterReport struct {
	Status    string `json:"status"` // "registered" | "needs_human"
	Detail    string `json:"detail"`
	RequestID string `json:"request_id,omitempty"`
	URL       string `json:"url,omitempty"`
}

var humanMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bcaptcha\b`),
	regexp.MustCompile(`(?i)\brecaptcha\b`),
	regexp.MustCompile(`(?i)\bhcaptcha\b`),
	regexp.MustCompile(`(?i)\bturnstile\b`),
	regexp.MustCompile(`(?i)\bverification code\b`),
	regexp.MustCompile(`(?i)\bone[- ]time (code|password)\b`),
	regexp.MustCompile(`(?i)\bsms\b`),
	regexp.MustCompile(`(?i)\bphone number\b`),
	regexp.MustCompile(`(?i)验证码|短信|手机号|人机验证`),
}

// Register is a single, human-gated attempt at self-registration.
//
// It never bypasses a challenge: if the signup page or the response shows a
// CAPTCHA / SMS / OTP gate, youkai stops and says so. Email verification is not
// guessed either - an operator supplies the verification_url from the mailbox.
func (s *Service) Register(ctx context.Context, args map[string]any) (ledger.Observation, RegisterReport, error) {
	rep := RegisterReport{Status: "needs_human"}
	scope := s.Env.Guard.Scope()
	if scope == nil || !scope.AllowAccountProvisioning {
		return ledger.Observation{}, rep, fmt.Errorf(
			"accounts: 自助注册未授权:需要 scope.allow_account_provisioning=true(档 2 写操作)")
	}

	// Path A: the operator already fetched the verification link.
	if vurl, _ := args["verification_url"].(string); strings.TrimSpace(vurl) != "" {
		res, err := s.Env.Guard.Do(ctx, discipline.Request{
			Method: "GET", URL: vurl, Purpose: "accounts_register", FollowRedirects: true,
		})
		if err != nil {
			return ledger.Observation{}, rep, err
		}
		rep.Status = "registered"
		rep.Detail = fmt.Sprintf("已用人工提供的验证链接完成验证(HTTP %d)", res.Status)
		rep.RequestID = res.RequestID
		rep.URL = vurl
		obs := ledger.Observation{
			Facts: []ledger.FactSeed{{
				Statement: "账号验证链接已使用:" + vurl,
				Evidence:  map[string]any{"request_id": res.RequestID, "status": res.Status},
				Tags:      []string{"account", "register"},
			}},
			RequestIDs: []string{res.RequestID},
			Summary:    "register via operator verification_url",
		}
		return obs, rep, nil
	}

	// Path B: one signup submission, then look for a challenge.
	signupURL, _ := args["signup_url"].(string)
	if strings.TrimSpace(signupURL) == "" {
		return ledger.Observation{}, rep, fmt.Errorf("accounts: 注册需要 signup_url 或 verification_url")
	}
	fields := map[string]string{}
	if raw, ok := args["fields"].(map[string]any); ok {
		for k, v := range raw {
			if sv, ok := v.(string); ok {
				fields[k] = sv
			}
		}
	}
	if hasChallengeField(fields) {
		rep.Detail = "表单里出现 CAPTCHA/手机号/OTP 字段:youkai 不提交、不绕过。请人工完成注册后提供会话。"
		return ledger.Observation{}, rep, fmt.Errorf("%w:%s", ErrNeedsHuman, rep.Detail)
	}
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	res, err := s.Env.Guard.Do(ctx, discipline.Request{
		Method: "POST", URL: signupURL, Purpose: "accounts_register", FollowRedirects: false,
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    []byte(form.Encode()),
	})
	if err != nil {
		return ledger.Observation{}, rep, err
	}
	if ch := detectChallenge(res.Text()); ch != "" {
		rep.Detail = "注册响应出现人工校验(" + ch + "):youkai 停在这里,不重试、不绕过。"
		rep.RequestID = res.RequestID
		rep.URL = signupURL
		obs := ledger.Observation{
			Facts: []ledger.FactSeed{{
				Statement: "自助注册撞到人工校验:" + ch,
				Evidence:  map[string]any{"request_id": res.RequestID, "status": res.Status},
				Tags:      []string{"account", "register", "needs-human"},
			}},
			RequestIDs: []string{res.RequestID},
			Summary:    "register needs_human: " + ch,
		}
		return obs, rep, fmt.Errorf("%w:%s", ErrNeedsHuman, rep.Detail)
	}
	rep.Status = "registered"
	rep.Detail = fmt.Sprintf("已提交一次注册(HTTP %d);邮箱验证需人工提供 verification_url", res.Status)
	rep.RequestID = res.RequestID
	rep.URL = signupURL
	obs := ledger.Observation{
		Facts: []ledger.FactSeed{{
			Statement: "自助注册已提交一次:" + signupURL,
			Evidence:  map[string]any{"request_id": res.RequestID, "status": res.Status},
			Tags:      []string{"account", "register"},
		}},
		RequestIDs: []string{res.RequestID},
		Summary:    "register submitted once",
	}
	return obs, rep, nil
}

func hasChallengeField(fields map[string]string) bool {
	for k := range fields {
		low := strings.ToLower(k)
		for _, needle := range []string{"captcha", "recaptcha", "hcaptcha", "turnstile", "otp", "sms", "phone", "verification_code"} {
			if strings.Contains(low, needle) {
				return true
			}
		}
	}
	return false
}

func detectChallenge(text string) string {
	for _, re := range humanMarkers {
		if loc := re.FindString(text); loc != "" {
			return strings.ToLower(loc)
		}
	}
	return ""
}

// ---- reachability ----------------------------------------------------------

// ReachEdge is one identity's access to one endpoint.
type ReachEdge struct {
	Identity  string `json:"identity"`
	URL       string `json:"url"`
	Status    int    `json:"status"`
	Length    int    `json:"length"`
	RequestID string `json:"request_id"`
}

// Reachability builds a read-only multi-identity reachability picture.
//
// A valid high-authorisation record covering every host is required, and the
// only operation is a GET per identity per endpoint. No lateral movement, no
// tunnelling, no credential use beyond the stored sessions.
func (s *Service) Reachability(ctx context.Context, urls []string, sessions []string, highAuthPath string, includeAnonymous bool) (ledger.Observation, []ReachEdge, error) {
	var obs ledger.Observation
	var edges []ReachEdge
	if len(urls) == 0 {
		return obs, edges, fmt.Errorf("accounts: reachability 需要至少一个 url")
	}
	key, err := discipline.KeyFromEnv()
	if err != nil {
		return obs, edges, fmt.Errorf("accounts: reachability 需要 high-auth 授权:%w", err)
	}
	if strings.TrimSpace(highAuthPath) == "" {
		return obs, edges, fmt.Errorf("accounts: reachability 需要 high_auth_path(一份签名的 read-only 授权文件)")
	}
	rec, err := discipline.LoadHighAuth(highAuthPath)
	if err != nil {
		return obs, edges, err
	}
	grant, err := rec.Verify(key, Now())
	if err != nil {
		return obs, edges, fmt.Errorf("accounts: high-auth 校验失败:%w", err)
	}
	for _, u := range urls {
		if !grant.Covers(u) {
			return obs, edges, fmt.Errorf("accounts: high-auth 记录未覆盖目标 %q", discipline.HostOf(u))
		}
	}

	identities := sessions
	if len(identities) == 0 && s.Manifest != nil {
		identities = s.Manifest.Names()
	}
	type idSession struct {
		name    string
		headers map[string]string
	}
	var ids []idSession
	for _, name := range identities {
		sess, err := s.Sessions.Load(name)
		if err != nil {
			return obs, edges, fmt.Errorf("accounts: reachability 需要会话 %q:%w", name, err)
		}
		ids = append(ids, idSession{name: name, headers: sess.Headers})
	}
	if includeAnonymous {
		ids = append(ids, idSession{name: "anonymous", headers: nil})
	}
	if len(ids) == 0 {
		return obs, edges, fmt.Errorf("accounts: reachability 没有可用身份")
	}

	for _, u := range urls {
		for _, id := range ids {
			res, err := s.Env.Guard.Do(ctx, discipline.Request{
				Method: "GET", URL: u, Headers: id.headers,
				Purpose: "reachability", FollowRedirects: true,
			})
			if err != nil {
				return obs, edges, fmt.Errorf("accounts: reachability %s → %s:%w", id.name, u, err)
			}
			edges = append(edges, ReachEdge{
				Identity: id.name, URL: u, Status: res.Status,
				Length: len(res.Body), RequestID: res.RequestID,
			})
			obs.Facts = append(obs.Facts, ledger.FactSeed{
				Statement: fmt.Sprintf("可达性:%s 访问 %s → HTTP %d", id.name, u, res.Status),
				Evidence: map[string]any{
					"request_id": res.RequestID, "status": res.Status,
					"identity": id.name, "url": u, "high_auth_nonce": grant.Nonce,
				},
				Tags:    []string{"reachability", "identity"},
				Anchors: []string{"host:" + discipline.HostOf(u)},
			})
			obs.RequestIDs = append(obs.RequestIDs, res.RequestID)
		}
	}
	obs.Summary = fmt.Sprintf("reachability: %d identities × %d endpoints", len(ids), len(urls))
	return obs, edges, nil
}

// ---- helpers ---------------------------------------------------------------

func (s *Service) selectAccounts(only []string) ([]Account, error) {
	if s.Manifest == nil {
		return nil, fmt.Errorf("accounts: 没有账号清单")
	}
	if len(only) == 0 {
		return s.Manifest.Accounts, nil
	}
	want := map[string]bool{}
	for _, n := range only {
		want[strings.TrimSpace(n)] = true
	}
	var out []Account
	for _, a := range s.Manifest.Accounts {
		if want[a.Name] {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("accounts: --only 没有匹配的账号")
	}
	return out, nil
}

func (s *Service) absoluteURL(a Account, raw string) string {
	if strings.Contains(raw, "://") {
		return raw
	}
	base := ""
	if s.Manifest != nil {
		base = s.Manifest.Base(a)
	}
	if base == "" {
		if origin, err := parseOrigin(a.Login.URL); err == nil {
			base = origin
		}
	}
	if base == "" {
		return raw
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(raw, "/")
}

// extractBySpec pulls a value out of a response body per the seed spec.
func extractBySpec(body string, spec SeedExtract) string {
	if strings.EqualFold(spec.From, "regex") && spec.Pattern != "" {
		re, err := regexp.Compile(spec.Pattern)
		if err != nil {
			return ""
		}
		m := re.FindStringSubmatch(body)
		if len(m) > 1 {
			return m[1]
		}
		if len(m) == 1 {
			return m[0]
		}
		return ""
	}
	path := spec.Path
	if path == "" {
		path = "id"
	}
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return ""
	}
	for _, seg := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = m[seg]
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}
