package report

import "strings"

// RemediationFor returns the fix advice for a finding kind.
//
// Two rules shape this table:
//
//   - it is generic best practice, never target-specific: the text must be safe to
//     hand to the asset owner as-is, and it must not leak what was found;
//   - an unknown kind returns "" rather than a confident-sounding guess. "I do not
//     have advice for this type" is a better answer than advice that sounds right.
func RemediationFor(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "sqli":
		return "所有查询改用参数化语句(预处理),不要用字符串拼接 SQL;对受影响参数加服务端类型/长度校验;" +
			"关闭详细数据库错误回显。"
	case "ssti":
		return "不要把用户输入拼进模板源;使用沙箱化模板引擎,对变量做转义;模板与数据严格分离。"
	case "xss", "reflection", "header-reflection":
		return "在输出处做上下文相关编码(HTML/属性/JS/URL 各自规则),不要用黑名单过滤;" +
			"同时启用严格 CSP 作为第二道防线。"
	case "ssrf":
		return "出站请求做目的地白名单(拒绝内网与元数据地址段),禁止跟随重定向或对重定向目标二次校验;" +
			"把取回内容的协议限制在必要范围。"
	case "path", "lfi", "traversal":
		return "不要用用户输入拼接路径;先规范化再与允许根目录比对(前缀校验用分隔符边界)," +
			"必要时用固定 id 映射文件,而不是直接传文件名。"
	case "cmdi":
		return "不要通过 shell 拼接命令;改用带参数数组的进程调用,并对允许的取值做白名单校验。"
	case "xxe":
		return "解析 XML 时禁用外部实体与 DTD(如 DisallowDoctype=true、禁止外部实体解析)," +
			"优先改用不解析实体的数据格式。"
	case "upload", "unrestricted-upload":
		return "按内容(而不是扩展名/Content-Type)校验类型;把上传文件存到 Web 根目录之外并用随机文件名;" +
			"下载时强制 Content-Disposition: attachment 且不按上传类型解析。"
	case "idor", "bola":
		return "在服务端对每次对象访问做归属校验(对象级授权),不依赖前端或可猜测的 id;" +
			"同一资源在不同身份下应得到一致的授权判定。"
	case "bfla", "authz", "missing-authz":
		return "在每个接口上做服务端功能级授权校验(角色/权限矩阵),不要只靠隐藏入口或前端路由;" +
			"默认拒绝,按角色显式放行。"
	case "redirect", "open-redirect":
		return "跳转目标只允许同站相对路径或预置白名单;拒绝协议相对(//host)与含用户信息的 URL。"
	case "cors":
		return "不要反射任意 Origin;需要凭证的接口固定可信来源,并显式设置 Vary: Origin;" +
			"不需要跨域的接口不要回 ACAO。"
	case "jwt":
		return "服务端固定接受的算法(不要信任头部 alg),校验签名、exp/nbf 与 aud/iss;" +
			"拒绝 none 算法;密钥从环境/密钥管理读取,及时轮换。"
	case "oauth":
		return "强制 PKCE 与足够熵的 state,严格白名单校验 redirect_uri(精确匹配),移除隐式流;" +
			"scope 按最小化签发。"
	case "exposure", "git", "backup":
		return "把版本库、备份与配置移出 Web 根目录,并在网关层拦截常见探测路径;" +
			"发布流程里加一步产物检查。"
	case "headers":
		return "补齐安全响应头(CSP、X-Content-Type-Options、Referrer-Policy、X-Frame-Options 或 frame-ancestors),并验证不影响业务。"
	case "secret":
		return "立刻吊销并轮换该凭据;改为从环境变量或密钥管理注入,加入提交前扫描防止再次入库。"
	case "security-header", "version":
		return "收敛暴露面:移除精确版本号与多余指纹,补齐安全响应头。"
	case "blind_screen", "obfuscation":
		return "这类是分析线索而非目标缺陷:若确为生产样本,建议结合结构证据复核,不要据此对第三方系统动手。"
	}
	return ""
}

// RemediationOrEmpty keeps the "unknown kind stays blank" rule in one place.
func RemediationOrEmpty(kind string) string { return RemediationFor(kind) }
