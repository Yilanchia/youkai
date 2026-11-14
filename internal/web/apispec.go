package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// API schema ingestion: turn a documented API into a surface youkai can test.
//
// The value here is leverage. The authorisation engine (role_matrix, compare) is
// the crown of this product, but it could only work on endpoints a crawl happened
// to find. An OpenAPI document is the whole documented surface in one file.
//
// The safety rule that makes it trustworthy: a spec is DATA, not instructions.
//   - it is parsed, never executed;
//   - external `$ref`s are recorded as unresolved and never fetched;
//   - every endpoint is normalised and checked against the passport: an endpoint the
//     spec declares but the passport does not cover is reported, never testable;
//   - nothing is requested to "verify" an endpoint. This capability only lays out
//     the surface; crawl/role_matrix decide what to touch.

const (
	// maxSpecBytes bounds what we will parse. A "spec" larger than this is either
	// not a spec or an attempt to make us allocate our way to death.
	maxSpecBytes = 4 << 20
	// maxSpecEndpoints bounds the surface a single document can add.
	maxSpecEndpoints = 500
)

// specEndpoint is one normalised operation.
type specEndpoint struct {
	Path        string
	Method      string
	Auth        bool
	NeedsSample bool // path parameters need a concrete id
	Summary     string
}

// specDoc is the subset of OpenAPI 2/3 we read.
type specDoc struct {
	OpenAPI             string                 `json:"openapi"`
	Swagger             string                 `json:"swagger"`
	Host                string                 `json:"host"`
	BasePath            string                 `json:"basePath"`
	Schemes             []string               `json:"schemes"`
	Servers             []struct{ URL string } `json:"servers"`
	Security            []map[string]any       `json:"security"`
	SecurityDefinitions map[string]any         `json:"securityDefinitions"`
	Components          struct {
		SecuritySchemes map[string]any `json:"securitySchemes"`
	} `json:"components"`
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

func runAPISpec(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL := strings.TrimSpace(argString(args, "url"))
	path := strings.TrimSpace(argString(args, "path"))
	if rawURL == "" && path == "" {
		return ledger.Observation{}, fmt.Errorf(`web: api_spec: 需要 "url"(经 guard 拉取)或 "path"(本地文件)`)
	}

	b := newObs()
	var (
		body    []byte
		reqID   string
		specURL string
	)
	switch {
	case rawURL != "":
		res, err := do(ctx, env, discipline.Request{
			Method: "GET", URL: rawURL, Purpose: "api_spec", FollowRedirects: true,
		})
		if err != nil {
			return ledger.Observation{}, fmt.Errorf("web: api_spec: %w", err)
		}
		b.requestID(res.RequestID)
		reqID = res.RequestID
		specURL = res.FinalURL
		if specURL == "" {
			specURL = rawURL
		}
		body = res.Body
		if res.Truncated || len(body) > maxSpecBytes {
			b.fact("API 文档超过解析上限,只解析了前 "+fmt.Sprint(maxSpecBytes/1024)+"KiB",
				map[string]any{"request_id": reqID, "url": specURL}, "api-spec", "truncated")
			body = body[:min(len(body), maxSpecBytes)]
		}
	case path != "":
		raw, err := readLocalSpec(path)
		if err != nil {
			return ledger.Observation{}, fmt.Errorf("web: api_spec: %w", err)
		}
		body = raw
		specURL = "file://" + path
		b.fact("从本地文件解析 API 文档:"+path, map[string]any{"request_id": "local:" + path, "url": specURL}, "api-spec", "local")
		// A local spec has no audit row; the capability still needs one anchor.
		if reqID == "" {
			reqID = "local:" + path
			b.requestID(reqID)
		}
	}

	doc, endpoints, warnings, err := parseAPISpec(body, specURL)
	if err != nil {
		b.fact("API 文档解析失败:"+err.Error(), map[string]any{"request_id": reqID, "url": specURL}, "api-spec", "parse-error")
		return b.obs, nil
	}
	for _, w := range warnings {
		b.fact("API 文档提示:"+w, map[string]any{"request_id": reqID, "url": specURL}, "api-spec", "warning")
	}

	version := doc.OpenAPI
	if version == "" {
		version = "swagger " + doc.Swagger
	}
	authSchemes := len(doc.Components.SecuritySchemes) + len(doc.SecurityDefinitions)
	b.fact(fmt.Sprintf("API 文档可读:%s,声明 %d 个操作,%d 个认证方案",
		version, len(endpoints), authSchemes),
		map[string]any{"request_id": reqID, "url": specURL, "operations": len(endpoints)},
		"api-spec", "source=openapi")
	b.finding(ledger.FindingSeed{
		Title:    "API 文档可公开读取",
		Severity: "info",
		Kind:     "exposure",
		Where:    specURL,
		Detail: fmt.Sprintf("文档（%s）可直接读取,声明了 %d 个操作;建议确认是否应对外开放。",
			version, len(endpoints)),
		Evidence: map[string]any{"request_id": reqID, "url": specURL, "source": "openapi"},
		Tags:     []string{"api-spec", "openapi", "exposure"},
		Anchors:  []string{"surface:" + specURL},
	})

	scope := env.Guard.Scope()
	inScope, outScope := 0, 0
	for _, ep := range endpoints {
		target := joinSpecURL(specURL, ep.Path, doc)
		if target == "" {
			continue
		}
		if _, err := scope.Check(target); err != nil {
			outScope++
			b.fact("spec 声明了但超出 scope(不登记为可测):"+ep.Method+" "+target,
				map[string]any{"request_id": reqID, "url": target},
				"api-spec", "out-of-scope")
			continue
		}
		inScope++
		write := ep.Method != "GET" && ep.Method != "HEAD" && ep.Method != "OPTIONS"
		tags := []string{"api-spec", "openapi", "source=openapi"}
		if ep.Auth {
			tags = append(tags, "auth-required")
		}
		if write {
			tags = append(tags, "write", "tier-hint=proof")
		}
		if ep.NeedsSample {
			tags = append(tags, "needs-sample")
		}
		b.asset("endpoint", target)
		b.fact(fmt.Sprintf("文档化端点:%s %s%s", ep.Method, target, endpointNotes(ep)),
			map[string]any{"request_id": reqID, "url": target, "method": ep.Method, "source": "openapi"},
			tags...)
	}

	b.setSummary(fmt.Sprintf("api_spec: %d 个操作,登记 %d 个在 scope 内,%d 个超 scope",
		len(endpoints), inScope, outScope))
	return b.obs, nil
}

func endpointNotes(ep specEndpoint) string {
	var notes []string
	if ep.Auth {
		notes = append(notes, "需认证")
	}
	if ep.NeedsSample {
		notes = append(notes, "含路径参数,需样本 id")
	}
	if ep.Method != "GET" {
		notes = append(notes, "写方法:自治不碰")
	}
	if len(notes) == 0 {
		return ""
	}
	return "(" + strings.Join(notes, ";") + ")"
}

func readLocalSpec(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("读取本地文档: %w", err)
	}
	if info.Size() > maxSpecBytes {
		return nil, fmt.Errorf("本地文档超过 %d KiB", maxSpecBytes/1024)
	}
	return os.ReadFile(path)
}

// parseAPISpec turns JSON or YAML bytes into operations.
//
// YAML is converted to JSON first so there is exactly one decoding path: two
// decoders would eventually disagree about something that matters (a null vs an
// empty object), and this input is attacker-controlled.
func parseAPISpec(raw []byte, specURL string) (specDoc, []specEndpoint, []string, error) {
	body := raw
	if !looksLikeJSON(body) {
		var generic any
		if err := yaml.Unmarshal(raw, &generic); err != nil {
			return specDoc{}, nil, nil, fmt.Errorf("不是可解析的 JSON/YAML: %w", err)
		}
		converted, err := json.Marshal(normaliseYAML(generic))
		if err != nil {
			return specDoc{}, nil, nil, err
		}
		body = converted
	}
	var doc specDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return specDoc{}, nil, nil, fmt.Errorf("不是 OpenAPI/Swagger 结构: %w", err)
	}
	if doc.OpenAPI == "" && doc.Swagger == "" {
		return specDoc{}, nil, nil, fmt.Errorf("缺少 openapi/swagger 版本字段")
	}

	var warnings []string
	var endpoints []specEndpoint
	methods := 0
	for _, rawPath := range sortedPathKeys(doc.Paths) {
		ops := doc.Paths[rawPath]
		for _, m := range []string{"get", "post", "put", "patch", "delete", "options", "head", "trace"} {
			rawOp, ok := ops[m]
			if !ok {
				continue
			}
			methods++
			if len(endpoints) >= maxSpecEndpoints {
				warnings = append(warnings, fmt.Sprintf("操作数超过 %d,其余未登记", maxSpecEndpoints))
				break
			}
			var op struct {
				Summary  string          `json:"summary"`
				Security json.RawMessage `json:"security"`
			}
			_ = json.Unmarshal(rawOp, &op)
			endpoints = append(endpoints, specEndpoint{
				Path:        rawPath,
				Method:      strings.ToUpper(m),
				Auth:        len(doc.Security) > 0 || len(op.Security) > 0,
				NeedsSample: strings.Contains(rawPath, "{"),
				Summary:     strings.TrimSpace(op.Summary),
			})
		}
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		if endpoints[i].Path != endpoints[j].Path {
			return endpoints[i].Path < endpoints[j].Path
		}
		return endpoints[i].Method < endpoints[j].Method
	})
	return doc, endpoints, warnings, nil
}

// joinSpecURL resolves a documented path against the document's base.
//
// Priority: an absolute server URL from the document, else the origin the document
// was fetched from. A server URL pointing somewhere else is still allowed here - the
// caller checks it against the passport, which is the only authority on reachability.
func joinSpecURL(specURL, path string, doc specDoc) string {
	base := ""
	for _, s := range doc.Servers {
		if strings.TrimSpace(s.URL) != "" {
			base = strings.TrimRight(strings.TrimSpace(s.URL), "/")
			break
		}
	}
	if base == "" && doc.Host != "" { // Swagger 2
		scheme := "https"
		if len(doc.Schemes) > 0 {
			scheme = doc.Schemes[0]
		}
		base = scheme + "://" + doc.Host + strings.TrimRight(doc.BasePath, "/")
	}
	if base == "" {
		if u, err := url.Parse(specURL); err == nil && u.Scheme != "" {
			base = u.Scheme + "://" + u.Host
		}
	}
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

func sortedPathKeys(paths map[string]map[string]json.RawMessage) []string {
	out := make([]string, 0, len(paths))
	for k := range paths {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func looksLikeJSON(raw []byte) bool {
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// normaliseYAML converts map[any]any into map[string]any so encoding/json accepts it.
func normaliseYAML(v any) any {
	switch t := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[fmt.Sprint(k)] = normaliseYAML(val)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normaliseYAML(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = normaliseYAML(e)
		}
		return out
	}
	return v
}
