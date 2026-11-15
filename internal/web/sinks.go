package web

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// Existence probes for the sinks the whitebox package can name.
//
// One rule binds all of them: touch the door, do not open it. Every probe below
// either observes a callback or a timing/status difference. None of them reads,
// stores or returns what the target sends back beyond a fixed-size prefix that the
// existing builder already redacts.
//
// Class -> what "hit" means:
//
//	ssrf  the target fetched our canary URL (we were the destination)
//	xxe   the target's XML parser fetched our canary URL
//	path  a path that climbs out of the web root returned the marker we planted
//	cmdi  the parameter made the server pause (a sleep, nothing else)
//	upload a harmless text marker was accepted (never executed, never fetched twice)
//	deserialize   NOT probed. There is no safe existence check, so it is handed to a human.

const (
	// ssrfWait is how long we watch the canary after sending the request.
	ssrfWait = 3 * time.Second
	// cmdiDelay is the sleep the probe asks the target to perform.
	cmdiDelay = 2 * time.Second
	// cmdiThreshold is how much slower than baseline counts as caused by us.
	cmdiThreshold = 1200 * time.Millisecond
	// maxMarkerBytes caps the response prefix we look at for the marker.
	maxMarkerBytes = 4096
)

// probeSSRF replaces the parameter with a canary URL and waits to be called back.
func (p *paramProbe) probeSSRF(original string) {
	c := canaryOf()
	cb, token, err := c.Token()
	if err != nil {
		p.b.fact("SSRF 探测未执行:canary 端点无法启动(无法判定,不代表不存在)",
			map[string]any{"request_id": lastRequestID(p)}, "param:ssrf", "incomplete")
		return
	}
	payloads := []string{cb, url.QueryEscape(cb)}
	for _, payload := range payloads {
		if p.budget <= 0 {
			break
		}
		target, err := withParamValue(p.rawURL, p.name, payload)
		if err != nil {
			return
		}
		res, err := p.request(target, "param:ssrf")
		if err != nil {
			continue
		}
		_ = res // the response body is irrelevant: the evidence is the callback
		if c.Wait(token, ssrfWait) {
			p.hits["ssrf"] = true
			p.b.finding(ledger.FindingSeed{
				Title:    "参数可触发服务端请求(SSRF)",
				Severity: "high",
				Kind:     "ssrf",
				Where:    p.rawURL,
				Detail: fmt.Sprintf("把参数 %s 换成 youkai 的 canary URL 后,目标服务器主动请求了该地址(%d 次)。"+
					"只记录触达事实,不读取目标取回的任何内容。", p.name, c.Hits(token)),
				Counter: "canary 被触达只证明'服务端会对可控 URL 发请求';能否访问内网/元数据需人工在授权下判断",
				Evidence: map[string]any{
					"request_id": res.RequestID, "canary_hits": c.Hits(token),
					"canary_remote": c.RemoteOf(token), "probe": "ssrf",
				},
			})
			p.b.fact(fmt.Sprintf("SSRF 存在性证据:%s 的参数 %s 让目标请求了 canary(来源 %s)",
				p.rawURL, p.name, c.RemoteOf(token)),
				map[string]any{"request_id": res.RequestID, "canary_hits": c.Hits(token)}, "param:ssrf")
			return
		}
	}
	// Not reached: say so without concluding the target is safe. A target behind
	// NAT cannot call us back, and "could not judge" is the honest label.
	p.b.fact("SSRF 未能判定:canary 未被触达(可能是目标无法回连,不等于不存在)",
		map[string]any{"request_id": lastRequestID(p)}, "param:ssrf", "undetermined")
}

// probeXXE posts an XML body whose external entity points at the canary.
func (p *paramProbe) probeXXE(original string) {
	c := canaryOf()
	cb, token, err := c.Token()
	if err != nil {
		p.b.fact("XXE 探测未执行:canary 端点无法启动(无法判定)", map[string]any{}, "param:xxe", "incomplete")
		return
	}
	body := fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY yk SYSTEM "%s">]>
<root><probe>&yk;</probe></root>`, cb)
	if p.budget <= 0 {
		return
	}
	res, err := do(p.ctx, p.env, discipline.Request{
		Method:  "POST",
		URL:     p.rawURL,
		Headers: mergeContentType(p.headers, "application/xml"),
		Body:    []byte(body),
		Purpose: "param:xxe",
	})
	if err != nil {
		p.b.fact("XXE 探测未执行:"+err.Error(), map[string]any{}, "param:xxe", "incomplete")
		return
	}
	p.b.requestID(res.RequestID)
	p.probes++
	if c.Wait(token, ssrfWait) {
		p.hits["xxe"] = true
		p.b.finding(ledger.FindingSeed{
			Title:    "XML 外部实体被解析(XXE)",
			Severity: "high",
			Kind:     "xxe",
			Where:    p.rawURL,
			Detail: "提交的 XML 里外部实体指向 youkai 的 canary,目标解析器请求了该地址:" +
				"说明外部实体被展开。本次没有携带任何本地文件,也没有回带内容。",
			Counter:  "只证明解析器会展开外部实体;能否读取本地文件需人工验证",
			Evidence: map[string]any{"request_id": res.RequestID, "canary_hits": c.Hits(token), "probe": "xxe"},
		})
		p.b.fact("XXE 存在性证据:目标 XML 解析器请求了 canary", map[string]any{"request_id": res.RequestID}, "param:xxe")
		return
	}
	p.b.fact("XXE 未能判定:canary 未被触达(入口可能不是 XML,或目标无法回连)",
		map[string]any{"request_id": res.RequestID}, "param:xxe", "undetermined")
}

// probePathTraversal looks for a marker that should not be reachable through a
// traversal. It compares against a baseline of a random nonexistent name, and it
// never returns file content - only "the marker appeared".
func (p *paramProbe) probePathTraversal(original, marker string) {
	if marker == "" {
		marker = "youkai-path-marker"
	}
	base, err := p.request(p.rawURL, "param:path-baseline")
	if err != nil {
		p.b.fact("路径穿越探测未执行:基线请求失败", map[string]any{}, "param:path", "incomplete")
		return
	}
	baseBody := base.Text()
	baseLen := len(baseBody)
	// Depth varies by layout; three shapes cover the common roots.
	payloads := []string{
		"../" + marker + ".txt",
		"../../" + marker + ".txt",
		"....//" + marker + ".txt",
	}
	for _, payload := range payloads {
		if p.budget <= 0 {
			break
		}
		target, err := withParamValue(p.rawURL, p.name, payload)
		if err != nil {
			return
		}
		res, err := p.request(target, "param:path")
		if err != nil {
			continue
		}
		body := res.Text()
		if len(body) > maxMarkerBytes {
			body = body[:maxMarkerBytes]
		}
		if strings.Contains(body, marker) && !strings.Contains(baseBody, marker) {
			p.hits["path"] = true
			p.b.finding(ledger.FindingSeed{
				Title:    "参数可穿越目录读到 web 根之外的文件",
				Severity: "high",
				Kind:     "path-traversal",
				Where:    p.rawURL,
				Detail: fmt.Sprintf("参数 %s 传 %q 后,响应里出现了只应存在于 web 根之外的标记"+
					"(基线长度 %d,本次 %d)。只判断标记是否可达,没有保存文件内容。", p.name, payload, baseLen, len(body)),
				Counter: "标记可达说明路径没有被约束;影响范围取决于进程权限,需人工判断",
				Evidence: map[string]any{
					"request_id": res.RequestID, "payload": payload, "probe": "path",
					"baseline_len": baseLen, "hit_len": len(body),
				},
			})
			p.b.fact("路径穿越存在性证据:响应中出现根外标记", map[string]any{"request_id": res.RequestID}, "param:path")
			return
		}
	}
	p.b.fact("路径穿越无命中:所有越界路径都没有返回标记文件",
		map[string]any{"request_id": lastRequestID(p)}, "param:path", "no-hit", "param")
}

// probeCMDI measures time. It never asks the server to run anything that produces
// output: the only injected command is a sleep.
func (p *paramProbe) probeCMDI(original string) {
	base, err := p.request(p.rawURL, "param:cmdi-baseline")
	if err != nil {
		p.b.fact("命令注入探测未执行:基线请求失败", map[string]any{}, "param:cmdi", "incomplete")
		return
	}
	baseDur := time.Duration(base.TimingMS) * time.Millisecond
	if baseDur <= 0 {
		baseDur = 1 * time.Millisecond
	}
	sleepSeconds := int(cmdiDelay / time.Second)
	payloads := []string{
		original + "; sleep " + fmt.Sprint(sleepSeconds),
		original + " | sleep " + fmt.Sprint(sleepSeconds),
		original + "$(sleep " + fmt.Sprint(sleepSeconds) + ")",
	}
	attempts := 0
	for _, payload := range payloads {
		if p.budget <= 0 || attempts >= 2 {
			break
		}
		attempts++
		target, err := withParamValue(p.rawURL, p.name, payload)
		if err != nil {
			return
		}
		res, err := p.request(target, "param:cmdi")
		if err != nil {
			continue
		}
		if time.Duration(res.TimingMS)*time.Millisecond >= baseDur+cmdiThreshold {
			p.hits["cmdi"] = true
			p.b.finding(ledger.FindingSeed{
				Title:    "参数可能进入命令执行(时延证据)",
				Severity: "high",
				Kind:     "cmdi",
				Where:    p.rawURL,
				Detail: fmt.Sprintf("参数 %s 传入 %q 后,响应比基线慢 %d ms(基线 %d ms,本次 %d ms)。"+
					"注入的只有 sleep,没有执行任何产出型命令,也没有读取输出。",
					p.name, payload, res.TimingMS-baseDur.Milliseconds(),
					baseDur.Milliseconds(), res.TimingMS),
				Counter: "时延可能来自网络抖动;需人工用重复测量确认",
				Evidence: map[string]any{
					"request_id": res.RequestID, "payload_shape": "sleep", "probe": "cmdi",
					"baseline_ms": baseDur.Milliseconds(), "hit_ms": res.TimingMS,
				},
			})
			p.b.fact("命令注入存在性证据:sleep 造成了可测时延", map[string]any{"request_id": res.RequestID}, "param:cmdi")
			return
		}
	}
	p.b.fact("命令注入无命中:注入 sleep 后响应时间没有变化",
		map[string]any{"request_id": lastRequestID(p)}, "param:cmdi", "no-hit", "param")
}

// probeUpload sends one harmless text file and checks whether it was accepted.
// It never sends executable content and never asks the server to run it.
func (p *paramProbe) probeUpload(original string) {
	if p.budget <= 0 {
		return
	}
	token := randomToken()
	filename := "youkai-check-" + token[:8] + ".txt"
	body, contentType := multipartFile(p.name, filename, "youkai upload existence marker "+token)
	res, err := do(p.ctx, p.env, discipline.Request{
		Method:  "POST",
		URL:     p.rawURL,
		Headers: mergeContentType(p.headers, contentType),
		Body:    body,
		Purpose: "param:upload",
	})
	if err != nil {
		p.b.fact("文件上传探测未执行:"+err.Error(), map[string]any{}, "param:upload", "incomplete")
		return
	}
	p.b.requestID(res.RequestID)
	p.probes++
	text := res.Text()
	accepted := res.Status >= 200 && res.Status < 300
	if accepted && (strings.Contains(text, token) || res.Status == 201) {
		p.hits["upload"] = true
		p.b.finding(ledger.FindingSeed{
			Title:    "上传入口接受任意文本文件",
			Severity: "medium",
			Kind:     "upload",
			Where:    p.rawURL,
			Detail: "提交了一个纯文本标记文件(文件名 " + filename + "),服务端接受了它" +
				"(状态 " + fmt.Sprint(res.Status) + ")。没有上传可执行内容,也没有尝试运行。",
			Counter: "接受文本文件不等于可执行;是否危险取决于类型校验与存储位置,需人工判断",
			Evidence: map[string]any{
				"request_id": res.RequestID, "status": res.Status, "probe": "upload", "filename": filename,
			},
		})
		p.b.fact("上传存在性证据:纯文本标记文件被接受", map[string]any{"request_id": res.RequestID}, "param:upload")
		return
	}
	p.b.fact("文件上传无命中:标记文件没有被接受",
		map[string]any{"request_id": res.RequestID}, "param:upload", "no-hit", "param")
}

// ---- small helpers ---------------------------------------------------------

func lastRequestID(p *paramProbe) string {
	if len(p.b.obs.RequestIDs) == 0 {
		return ""
	}
	return p.b.obs.RequestIDs[len(p.b.obs.RequestIDs)-1]
}

func withParamValue(rawURL, name, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func mergeContentType(in map[string]string, ct string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	out["Content-Type"] = ct
	return out
}
