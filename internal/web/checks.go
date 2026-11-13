package web

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// This file holds the shared machinery: the single egress helper, the
// Observation builder that enforces "no request_id, no evidence", and the
// parsing/analysis helpers that scan, crawl, compare, and proof all reuse.

// guardOf is the package's only way to reach the network.
func guardOf(env *Env) (*discipline.Guard, error) {
	if env == nil || env.Guard == nil {
		// No guard means no passport, which discipline defines as "nothing may
		// happen". Wrap rather than replace so callers can errors.Is it.
		return nil, fmt.Errorf("web: %w", discipline.ErrNoScope)
	}
	return env.Guard, nil
}

// do sends exactly one request through the guard.
//
// There is deliberately no fallback: if the guard refuses, the capability
// refuses. Capabilities wrap the error with their own name.
func do(ctx context.Context, env *Env, req discipline.Request) (*discipline.Response, error) {
	g, err := guardOf(env)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Purpose) == "" {
		req.Purpose = "web"
	}
	res, err := g.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("web: guard returned no response")
	}
	return res, nil
}

// ---- observation builder ----------------------------------------------------

// obsBuilder assembles an Observation while keeping the invariants:
//
//   - a fact or finding without a request_id is dropped (it is not evidence);
//   - request ids are deduplicated and ordered;
//   - facts and findings are deduplicated on the keys the ledger would use.
type obsBuilder struct {
	obs      ledger.Observation
	reqSeen  map[string]bool
	factSeen map[string]bool
	findSeen map[string]bool
	assetSee map[string]bool
}

func newObs() *obsBuilder {
	return &obsBuilder{
		reqSeen:  map[string]bool{},
		factSeen: map[string]bool{},
		findSeen: map[string]bool{},
		assetSee: map[string]bool{},
	}
}

func (b *obsBuilder) requestID(id string) {
	id = strings.TrimSpace(id)
	if id == "" || b.reqSeen[id] {
		return
	}
	b.reqSeen[id] = true
	b.obs.RequestIDs = append(b.obs.RequestIDs, id)
}

func (b *obsBuilder) fact(statement string, evidence map[string]any, tags ...string) {
	statement = strings.TrimSpace(statement)
	if statement == "" {
		return
	}
	if requestIDOf(evidence) == "" {
		// A fact that cannot name the audit row behind it would be an
		// unverifiable claim. Fail closed.
		return
	}
	key := statement + "\x1f" + requestIDOf(evidence)
	if b.factSeen[key] {
		return
	}
	b.factSeen[key] = true
	b.obs.Facts = append(b.obs.Facts, ledger.FactSeed{
		Statement: statement,
		Evidence:  evidence,
		Tags:      dedupeTags(tags),
	})
}

func (b *obsBuilder) finding(f ledger.FindingSeed) {
	if strings.TrimSpace(f.Title) == "" || strings.TrimSpace(f.Where) == "" {
		return
	}
	if requestIDOf(f.Evidence) == "" {
		return
	}
	key := f.Kind + "\x1f" + f.Where + "\x1f" + f.Title
	if b.findSeen[key] {
		return
	}
	b.findSeen[key] = true
	f.Tags = dedupeTags(f.Tags)
	b.obs.Findings = append(b.obs.Findings, f)
}

func (b *obsBuilder) asset(kind, value string) {
	kind = strings.TrimSpace(kind)
	value = strings.TrimSpace(value)
	if kind == "" || value == "" {
		return
	}
	key := kind + "\x1f" + value
	if b.assetSee[key] {
		return
	}
	b.assetSee[key] = true
	b.obs.Assets = append(b.obs.Assets, ledger.AssetSeed{Kind: kind, Value: value})
}

func (b *obsBuilder) setSummary(s string) {
	b.obs.Summary = strings.TrimSpace(s)
}

// requestIDOf reads the audit id every evidence map must carry.
func requestIDOf(evidence map[string]any) string {
	if evidence == nil {
		return ""
	}
	s, _ := evidence["request_id"].(string)
	return strings.TrimSpace(s)
}

// respEvidence is the standard evidence shape for "this response exists".
func respEvidence(res *discipline.Response) map[string]any {
	if res == nil {
		return nil
	}
	return map[string]any{
		"request_id":   res.RequestID,
		"url":          res.URL,
		"status":       res.Status,
		"content_type": res.ContentType,
	}
}

// findingEvidence is the minimal evidence a finding needs: which audited request
// proves it, and what it returned. Bodies never go here.
func findingEvidence(res *discipline.Response) map[string]any {
	if res == nil {
		return nil
	}
	return map[string]any{
		"request_id": res.RequestID,
		"status":     res.Status,
	}
}

// ---- header / URL helpers ---------------------------------------------------

// headerGet is a case-insensitive lookup over the guard's sanitised header map.
func headerGet(headers map[string]string, name string) string {
	if len(headers) == 0 {
		return ""
	}
	if v, ok := headers[name]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// cookieNames extracts cookie names from a Set-Cookie header. The guard redacts
// the values (`sid=<redacted>`); names survive, and names are all the evidence
// needs. Attribute tokens are filtered out so a future, less redacted header
// cannot produce a bogus "cookie" called Path.
func cookieNames(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range allCookiesName.FindAllStringSubmatch(raw, 24) {
		if len(m) < 2 {
			continue
		}
		name := strings.TrimSpace(m[1])
		if name == "" || seen[name] {
			continue
		}
		switch strings.ToLower(name) {
		case "path", "domain", "expires", "max-age", "samesite", "secure", "httponly", "priority", "partitioned":
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func cloneHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// isHTMLResponse reports whether the guard saw an HTML document.
func isHTMLResponse(res *discipline.Response) bool {
	return res != nil && strings.Contains(strings.ToLower(res.ContentType), "html")
}

// originOf reduces a URL to scheme://host[:port]. It returns "" when the URL is
// not an absolute http(s) URL.
func originOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// isLoopbackHost mirrors Fairy's exception: plaintext HTTP on localhost is not
// worth a finding, because there is no network in the middle.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}

// withQueryParam returns rawURL with one query parameter replaced. The value is
// encoded by url.Values, which is the one URL-encoding layer every request gets.
func withQueryParam(rawURL, name, value string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("web: parse url %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("web: url %q has no host", rawURL)
	}
	if name == "" {
		return "", fmt.Errorf("web: empty parameter name")
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// normalizeLink resolves a link against its page and drops fragments. It returns
// "" for anything this package will not fetch (non-http schemes, empty values).
var skipLinkScheme = regexp.MustCompile(`(?i)^(?:javascript|mailto|tel|data|blob|about|file):`)

func normalizeLink(raw, pageURL string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || skipLinkScheme.MatchString(raw) {
		return ""
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(ref)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}

// ---- text analysis ----------------------------------------------------------

var (
	scriptBlockRx = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	styleBlockRx  = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style>`)
	tagRx         = regexp.MustCompile(`(?s)<[^>]*>`)
	spaceRx       = regexp.MustCompile(`\s+`)
)

// tokenizeText reduces HTML to at most max words, for similarity comparison.
func tokenizeText(body string, max int) []string {
	text := scriptBlockRx.ReplaceAllString(body, " ")
	text = styleBlockRx.ReplaceAllString(text, " ")
	text = tagRx.ReplaceAllString(text, " ")
	text = spaceRx.ReplaceAllString(strings.TrimSpace(text), " ")
	if text == "" {
		return nil
	}
	words := strings.Split(text, " ")
	if len(words) > max {
		words = words[:max]
	}
	return words
}

// jaccardText compares two documents by 4-word shingles. It is used for the
// dual-account body difference and the SQL boolean differential: both want
// "same page or not", not a byte hash (which dynamic pages defeat).
func jaccardText(a, b string) float64 {
	const shingle = 4
	left := wordShingles(tokenizeText(a, 4000), shingle)
	right := wordShingles(tokenizeText(b, 4000), shingle)
	if len(left) == 0 && len(right) == 0 {
		return 1
	}
	if len(left) == 0 || len(right) == 0 {
		return 0
	}
	small, large := left, right
	if len(right) < len(left) {
		small, large = right, left
	}
	overlap := 0
	for s := range small {
		if large[s] {
			overlap++
		}
	}
	return float64(overlap) / float64(len(left)+len(right)-overlap)
}

func wordShingles(words []string, size int) map[string]bool {
	out := make(map[string]bool)
	if size <= 0 || len(words) < size {
		return out
	}
	for i := 0; i+size <= len(words); i++ {
		out[strings.Join(words[i:i+size], " ")] = true
	}
	return out
}

// ---- reflection context -----------------------------------------------------

// Reflection context names. These describe where a marker landed in the raw
// response, which is the strongest judgement possible without a DOM backend.
const (
	contextNotReflected = "not-reflected"
	contextScript       = "script"
	contextStyle        = "style"
	contextEventAttr    = "event-handler"
	contextAttribute    = "attribute"
	contextComment      = "comment"
	contextText         = "text"
)

// currentAttribute names the attribute whose value the marker is inside.
//
// It works on the tag prefix (up to and including the opening quote) rather than
// on a full attribute regex, so a value like onclick="go('...')" with nested
// quotes still names "onclick".
func currentAttribute(tagText string) string {
	eq := strings.LastIndex(tagText, "=")
	if eq < 0 {
		return ""
	}
	prefix := strings.TrimRight(tagText[:eq], " \t\r\n")
	i := len(prefix)
	for i > 0 {
		c := prefix[i-1]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == ':' || c == '.' {
			i--
			continue
		}
		break
	}
	return prefix[i:]
}

// classifyReflection finds the first occurrence of marker in body and says which
// HTML/JS context it sits in. The ordering matters: a marker inside a comment is
// not a tag, and a marker inside a tag's attribute is not script text even when
// that tag is <script>.
func classifyReflection(body, marker string) string {
	if marker == "" {
		return contextNotReflected
	}
	at := strings.Index(body, marker)
	if at < 0 {
		return contextNotReflected
	}
	const window = 400
	start := at - window
	if start < 0 {
		start = 0
	}
	before := body[start:at]

	if isInsideComment(before) {
		return contextComment
	}
	if tagStart := strings.LastIndex(before, "<"); tagStart >= 0 && strings.LastIndex(before, ">") < tagStart {
		// Inside a tag: attribute value. Naming the attribute distinguishes an
		// event handler (executable) from a src/href (usually not).
		if attr := currentAttribute(before[tagStart:]); strings.HasPrefix(strings.ToLower(attr), "on") {
			return contextEventAttr
		}
		return contextAttribute
	}
	if isInsideElement(before, "script") {
		return contextScript
	}
	if isInsideElement(before, "style") {
		return contextStyle
	}
	return contextText
}

func isInsideComment(before string) bool {
	open := strings.LastIndex(before, "<!--")
	if open < 0 {
		return false
	}
	return strings.LastIndex(before, "-->") < open
}

// isInsideElement reports whether the text after the last opening tag of name has
// no closing tag after it.
func isInsideElement(before, name string) bool {
	open := strings.LastIndex(strings.ToLower(before), "<"+name)
	if open < 0 {
		return false
	}
	closeAt := strings.LastIndex(strings.ToLower(before), "</"+name)
	return closeAt < open
}
