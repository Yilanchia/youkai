# DEVPLAN-v0.13:白盒源码分析 — 读代码指导测试(学 Shannon,纯只读)

> 交付对象:实现者(DeepSeek)。配 ADR-004(吸收 Verdex)、DEVPLAN-v0.9(API schema)、ADR-006(点头批准)读。
> 目标:让 youkai 能读**操作员提供的 web 应用源码**,分析路由/数据流/信任边界,产出"**哪个入口的哪个参数可能通到哪个危险 sink**"
> 的**假设(hypothesis)**,用来**指导**黑盒测试该在哪挖 —— 而不是直接当漏洞报。补上 youkai 最大的能力缺口:白盒。

## 0. 为什么做这个(对照 16 项目全景)

- 文章里精神最近的 Shannon 核心路子:**先读源码理解架构/数据流/信任边界,再找入口**,比纯黑盒准得多;且坚持 "No exploit, no report"。
- youkai 现在是**纯黑盒**:只能扫爬到的东西,不认识应用内部结构。这是最大短板,也是最该补、最贴合纪律的一块(读代码纯只读)。
- youkai **已吸收 Verdex 的静态分析内核**(AST / source→sink 数据流 / secrets / SARIF),白盒 web 不从零写,是**把这套接到 web 域**。

## 0.5 不可动摇(本轮红线)

- **白盒产出是"假设"不是"发现"**:源码分析只产 `hypothesis`(线索),**必须**经黑盒探测命中才升 `candidate`,经操作员确认才 `verified`。
  **绝不因"代码看着危险"直接报漏洞**(Shannon 明文反对的,也是 youkai candidate≠verified 的底线)。
- **纯只读、纯本地**:只读操作员给的源码文件,不执行代码、不联网、不碰目标;源码分析这条路**不发任何请求**。
- **不泄源码正文/密钥**:分析产出只记 `file:line` + 符号名 + 数据流路径摘要;源码正文、硬编码密钥值不入账本/报告(secrets 只记脱敏预览,沿用 Verdex)。
- 白盒给出的入口若要主动验证,**仍走现有档位**:只读探测是档 1,param/写方法是档 2 停下点头。白盒不新增绕过。

## 1. 源码接入与路由/入口发现 `internal/whitebox`(P0)

**目标**:读操作员指定的源码目录,识别 web 框架、路由表、入口函数(controller/handler),登记成"代码侧入口"资产。

**能力**:`code_ingest`(档 1,纯本地)—— 参数 `path`(源码目录)。复用 Verdex 的 AST/语言识别内核。

**实现要点**:
- 支持主流栈的路由识别(至少:Express/Koa(JS)、Flask/Django(Py)、Spring(Java)、Gin/Echo(Go)、PHP 常见框架)——按文章里 Shannon 的覆盖面,先做 2–3 个最常见的,其余留扩展点。
- 每个路由登记 `asset(type=code-endpoint)`:method + path 模板 + handler 的 `file:line` + 认证中间件标记(有没有 auth guard)。
- **与 v0.9 的 API schema / 爬虫交叉锚定**:代码侧 `/orders/:id` 能和黑盒侧发现的 `/orders/1` 关联(同一端点的代码视角 + 网络视角)。

**验收**:喂一个小 Express/Flask 应用源码 → 路由表入账、每条带 handler file:line + 是否有 auth;源码正文不入账;全程零请求。

## 2. source→sink 数据流 → 假设 `internal/whitebox/dataflow.go`(P0,核心)

**目标**:把用户可控输入(source)追到危险操作(sink),对**可达的**路径产出类型化假设。

**source**:请求参数、body、header、路由参数、cookie。
**sink(按危险类分)**:SQL 拼接(SQLi)、命令执行(RCE)、文件路径(路径穿越/文件读写)、模板渲染(SSTI)、重定向(开放重定向)、HTTP 客户端(SSRF)、反序列化(反序列化漏洞)、HTML 输出(XSS)。

**产出 `hypothesis` 节点**(新的图节点类型,低于 candidate):
- `{entry: "GET /search", param: "q", sink: "sql-concat", path: "handler.js:12 → db.query:40", confidence: "code-only", note: "q 未见过滤直达 SQL 拼接"}`
- **confidence 固定是 `code-only`**,明确"这只是代码线索,未经运行验证"。

**喂给引擎做黑盒验证**:引擎派生规则加一条 —— 见到 `hypothesis(sink=sql-concat, entry, param)` + 该 entry 在 scope 内 → **派生对应的黑盒探测**(param SQLi 存在性,档 2 停下点头)。探测命中 → hypothesis 升 candidate(带代码+运行双证据);没命中 → hypothesis 标 `unconfirmed`(代码看着像、运行没复现,如实记录,不报)。

**实现要点**:
- 数据流分析是**启发式 + 标注**(复用 Verdex dataflow 的做法),不追求完备;明确标"可能漏报/误报"。
- 识别常见过滤/参数化(prepared statement、转义函数)→ 若 source 到 sink 中间有已知 sanitizer,降低或不产假设(减噪)。

**验收**:构造 source 直达 SQL 拼接的源码 → 产出 sql-concat 假设(confidence=code-only);中间加参数化查询 → 不产假设或标已缓解;
假设驱动引擎派出对应黑盒探测;探测没命中时假设标 unconfirmed 不升 candidate。

## 3. 信任边界与认证覆盖 `internal/whitebox/authz.go`(P1)

**目标**:从代码看哪些路由**缺认证/授权检查**,产出越权假设,交给账号层/role_matrix 黑盒验证。

**实现要点**:
- 识别路由是否被 auth 中间件覆盖;敏感操作(改数据、删除、管理端点)是否有授权检查。
- 产出 `hypothesis(type=missing-authz, entry)` → 引擎用现有 role_matrix/compare(多身份黑盒)验证 → 命中才 candidate。
- 结合 v0.9 账号层:代码说"这个端点没 auth 中间件" + 黑盒"低权账号能访问" = 双证据越权 candidate。

**验收**:一个缺 auth 的敏感路由 → 产 missing-authz 假设 → role_matrix 验证 → 低权可达则升 candidate;有 auth 的不产假设。

## 4. 报告整合 + SPA(P2)

- 报告里 verified 发现可同时带**代码证据(file:line + 数据流路径)+ 运行证据(request_id)**——这是 youkai 独有的"白盒+黑盒双证据",比纯黑盒报告强得多,写进四样证据的"证据"项。
- 假设/未确认项单独一节,明确"代码线索,未经运行确认,不构成发现"(诚实,不凑数)。
- 对话里 AI 能说"我读了代码,/search 的 q 可能有 SQL 注入,建议对它做存在性探测"——仍是建议,探测要点头、验证要人确认。
- SPA 加"源码"入口:选源码目录 → 看路由表/假设 → 一键让引擎去黑盒验证。

**验收**:一条代码+运行双证据的 verified 发现在报告里两种证据都在;未确认假设单列且措辞不当发现;对话里白盒建议仍走点头/确认。

## 落地顺序

1. 模块一(源码接入 + 路由/入口发现,复用 Verdex AST)。
2. 模块二(数据流 → 假设 + 喂引擎黑盒验证)—— 核心价值。
3. 模块三(认证覆盖 → 越权假设 → role_matrix 验证)。
4. 模块四(双证据报告 + SPA + 对话)。

**每步验收锚点**:白盒纯只读零请求;假设≠发现(必须黑盒命中才 candidate、人确认才 verified);源码正文/密钥不入账本;
代码看着危险但运行没复现 → 标 unconfirmed 不报;双证据发现代码+运行都在;档位/点头/Guard/档 3 墙全不变;`go test ./...` 全绿。

## 一句话

让 youkai 先读懂应用"里面长什么样",再去外面有的放矢地验证 —— 代码是地图,黑盒是脚印,人是裁判;
地图画得再像漏洞,没有脚印不算数。这正是 Shannon 的 "No exploit, no report",也是 youkai 一直的底线。
