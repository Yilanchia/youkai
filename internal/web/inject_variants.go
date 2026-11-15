package web

import (
	"fmt"
	"net/url"
	"strings"

	"youkai/internal/ledger"
)

// Two more existence checks that fit the same discipline as the rest.
//
//	nosql  an operator-shaped parameter changes the result set (Mongo-style $ne/$gt)
//	crlf   a newline in the parameter shows up as a response HEADER
//
// Neither reads data: the NoSQL probe compares response shapes, and the CRLF probe
// looks for its own header name in the response headers. No record is fetched, no
// injection is tuned.

// probeNoSQL tries the operator-shaped values a Mongo-backed query would consume.
func (p *paramProbe) probeNoSQL(original string) {
	base, err := p.request(p.rawURL, "param:nosql-baseline")
	if err != nil {
		p.b.fact("NoSQL 注入探测未执行:基线请求失败", map[string]any{}, "param:nosql", "incomplete")
		return
	}
	baseBody := base.Text()
	// Bracketed operator shapes (PHP/qs style) and a JSON-ish shape.
	payloads := []string{
		`{"$ne":""}`,
		`[$ne]=1`,
		`{"$gt":""}`,
	}
	for _, payload := range payloads {
		if p.budget <= 0 {
			break
		}
		target, err := withParamValue(p.rawURL, p.name, payload)
		if err != nil {
			return
		}
		res, err := p.request(target, "param:nosql")
		if err != nil {
			continue
		}
		body := res.Text()
		// Existence signal: the operator value produced a materially different
		// response than a plain value would (different status, or a very different
		// body shape). Deliberately coarse: this is a lead, not a proof.
		if res.Status != base.Status || bigEnoughDelta(len(baseBody), len(body)) {
			p.hits["nosql"] = true
			p.b.finding(ledger.FindingSeed{
				Title:    "参数接受 NoSQL 操作符形状并改变了结果",
				Severity: "medium",
				Kind:     "nosql",
				Where:    p.rawURL,
				Detail: fmt.Sprintf("把参数 %s 换成操作符形状后,响应与基线不同(状态 %d→%d,长度 %d→%d)。"+
					"只做了一次存在性比对,没有取任何记录。", p.name, base.Status, res.Status, len(baseBody), len(body)),
				Counter: "差异也可能来自参数校验失败或缓存;要定级需人工确认操作符真的进入了查询。",
				Evidence: map[string]any{
					"request_id": res.RequestID, "payload_shape": "operator", "probe": "nosql",
					"baseline_status": base.Status, "hit_status": res.Status,
				},
			})
			p.b.fact("NoSQL 存在性证据:操作符形状改变了响应", map[string]any{"request_id": res.RequestID}, "param:nosql")
			return
		}
	}
	p.b.fact("NoSQL 无命中:操作符形状与普通值响应一致",
		map[string]any{"request_id": lastRequestID(p)}, "param:nosql", "no-hit", "param")
}

// probeCRLF injects a newline plus a header and looks for that header coming back.
func (p *paramProbe) probeCRLF(original string) {
	marker := "X-Youkai-Probe-" + randomToken()[:8]
	// Both the encoded and the decoded shapes: some stacks decode before the
	// header split, some do not.
	payloads := []string{
		original + "%0d%0a" + marker + ":1",
		original + "\r\n" + marker + ":1",
	}
	for _, payload := range payloads {
		if p.budget <= 0 {
			break
		}
		target, err := withParamValueRaw(p.rawURL, p.name, payload)
		if err != nil {
			return
		}
		res, err := p.request(target, "param:crlf")
		if err != nil {
			continue
		}
		for name := range res.Header {
			if strings.EqualFold(name, marker) {
				p.hits["crlf"] = true
				p.b.finding(ledger.FindingSeed{
					Title:    "参数可注入响应头(CRLF)",
					Severity: "medium",
					Kind:     "crlf",
					Where:    p.rawURL,
					Detail: "参数里的换行把自造头 " + marker + " 送进了响应头。" +
						"只验证了头的存在,没有注入 Cookie、也没有覆盖已有头。",
					Counter: "不同反代的规范化策略不同;需人工确认该头能否被用来做缓存投毒或会话固定。",
					Evidence: map[string]any{
						"request_id": res.RequestID, "header": marker, "probe": "crlf",
					},
				})
				p.b.fact("CRLF 存在性证据:自造响应头出现", map[string]any{"request_id": res.RequestID}, "param:crlf")
				return
			}
		}
	}
	p.b.fact("CRLF 无命中:自造头没有出现在响应里",
		map[string]any{"request_id": lastRequestID(p)}, "param:crlf", "no-hit", "param")
}

// bigEnoughDelta is a coarse "materially different" test: a fifth of the larger
// body. Small diffs are noise (timestamps, request ids).
func bigEnoughDelta(a, b int) bool {
	if a == 0 && b == 0 {
		return false
	}
	larger := a
	if b > larger {
		larger = b
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return float64(diff)/float64(larger) > 0.2
}

// withParamValueRaw sets a parameter without re-encoding the value: the CRLF probe
// needs the bytes it constructed to survive into the request line.
func withParamValueRaw(rawURL, name, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// probeHeaderReflection looks for a header-looking value echoed into the body.
//
// Different from the CRLF probe: there the injected header appears in the RESPONSE
// HEADERS (an actual header injection). Here the value comes back inside the body,
// where it can reach a log viewer or an admin page. Only existence is judged.
func (p *paramProbe) probeHeaderReflection(original string) {
	marker := "youkai-hdr-" + randomToken()[:10]
	payloads := []string{
		marker,
		"1.2.3.4, " + marker,
	}
	for _, payload := range payloads {
		if p.budget <= 0 {
			break
		}
		target, err := withParamValue(p.rawURL, p.name, payload)
		if err != nil {
			return
		}
		res, err := p.request(target, "param:header")
		if err != nil {
			continue
		}
		body := res.Text()
		if len(body) > maxMarkerBytes {
			body = body[:maxMarkerBytes]
		}
		if strings.Contains(body, marker) {
			p.hits["header"] = true
			p.b.finding(ledger.FindingSeed{
				Title:    "参数值被反射进响应体(头部值直通)",
				Severity: "low",
				Kind:     "header-reflection",
				Where:    p.rawURL,
				Detail: "把带标记的值放进参数后,响应体里出现了同一个标记。若这个值本来取自 " +
					"X-Forwarded-* / Host 之类的头,说明头被无条件信任并回显。只判存在,不构造利用。",
				Counter: "回显本身不构成漏洞;危险程度取决于它是否进入日志、管理页或缓存键。",
				Evidence: map[string]any{
					"request_id": res.RequestID, "probe": "header", "marker_len": len(marker),
				},
			})
			p.b.fact("头部反射存在性证据:标记出现在响应体", map[string]any{"request_id": res.RequestID}, "param:header")
			return
		}
	}
	p.b.fact("头部反射无命中:标记没有出现在响应体",
		map[string]any{"request_id": lastRequestID(p)}, "param:header", "no-hit", "param")
}
