package report

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// counterFor is the default counter-argument per finding kind.
//
// The point of the field is to force a check before someone grades a finding, so
// the templates are concrete ("what would make this wrong and what is missing"),
// not reassurance. An unknown kind deliberately returns "" : the report marks the
// counter missing instead of inventing a plausible-sounding one.
func counterFor(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "bola":
		return "两个身份可能共享同一会话或被服务端做了同源豁免;要定级需再确认响应里出现的是对象内容而不是通用页,并确认 B 不是该对象的所有者。"
	case "sqli":
		return "错误签名/布尔差异也可能来自参数校验或 WAF;要定级需要可重复的时间差或 UNION 误差,当前只证存在性。"
	case "ssti":
		return "求值可能是模板引擎对输入的转义失败或客户端渲染;要定级需用不同表达式重复出相同结果。"
	case "xss", "reflection":
		return "反射存在不等于可执行:需确认落点在 script/事件属性且没有有效 CSP;当前只判定上下文,未执行载荷。"
	case "redirect":
		return "开放跳转可能被中间件白名单拦下;需确认 30x 的 Location 真的跨域。"
	case "cors":
		return "ACAO 反射也可能是静态站点;需确认带凭据响应里真的含敏感数据。"
	case "exposure", "git":
		return "文件可读不等于仓库完整;需确认响应确实是目标内容而非通用 200/网关页面。"
	case "headers", "header-missing":
		return "缺失安全头是配置观察,不构成可利用漏洞;要定级需与具体攻击面结合。"
	case "version-disclosure":
		return "版本号泄露本身不是漏洞;要定级需确认该版本存在可被利用的已知问题,且未修复。"
	case "scope-blocked":
		return "被拦断的请求说明页面尝试越界,但未发生真实越权;这是边界观察,不是目标漏洞。"
	case "authz":
		return "角色差异可能是设计如此(公开接口/不同视图);要定级需确认 B 身份拿到的是同一份数据而不是通用页面。"
	case "waf":
		return "只观察了拦截行为,未做绕过;拦截状态变化也可能来自限速或缓存。"
	case "ssrf":
		return "canary 被触达只证明服务端会对可控 URL 发请求;能否访问内网/云元数据、能读到什么,均需人工在授权下判断。"
	case "xxe":
		return "只证明 XML 解析器展开了外部实体;能否读本地文件、是否有回显,需人工验证。"
	case "path-traversal":
		return "标记文件可达说明路径未被约束;实际影响取决于进程权限与目录布局,需人工判定。"
	case "cmdi":
		return "时延可能来自网络抖动或服务端限速;要定级需可重复的多次测量,当前只做了一次存在性判断。"
	case "upload":
		return "接受文本文件不代表可执行:是否危险取决于类型校验、存储位置与后续访问方式。"
	case "binary":
		return "静态结论未执行样本;要定级需动态确认可达路径,当前仍为候选。"
	case "account":
		return "账号图层面的观察(登录/会话/归属);未做越权验证前不构成漏洞。"
	case "info":
		return "信息类观察,不构成可利用性结论。"
	}
	return ""
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
