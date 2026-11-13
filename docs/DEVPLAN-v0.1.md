# DEVPLAN-v0.1:youkai 实现文档 — Go 事件脑,两只手,档 1+2

> 交付对象:实现者(DeepSeek 等)。自包含,不依赖对话上下文。配 `ADR-002` 读。
> **更新(ADR-003)**:youkai 已平台化;本文档是**引擎核心规格**,仍有效(引擎在平台里照跑)。被更新的只有技术基线的
> "CLI-only / 零依赖 / JSON 账本" —— 状态改落 PostgreSQL、入口从 CLI 变 HTTP 服务;平台层(PG schema/API/SPA)另见 DEVPLAN-v0.2。
> 本文档只覆盖 **OSS 范围:档 1(只读)+ 档 2(人控证明级利用)+ 两只手接线 + 隔离墙**。
> **档 3(自动深度利用)内核不在本文档范围**:这里只规定隔离它的"墙"(编译期 build tag +
> 循环遇利用即停),不描述墙后任何实现。

## 0. 总原则(不可动摇)

- youkai 永不自己发目标请求;每个碰目标的动作都是一次 Fairy/Verdex MCP 调用。
- 自治循环**只跑档 1**。planner 一旦派档 2 动作,循环停、交人,过 Fairy high-auth + 单次 `confirm` 才执行。
- LLM 只提议类型化 intent;放行与否由闸门代码决定,与 LLM 无关。
- 永不自动 approve、永不自动利用、永不把 candidate 改 verified、失败不重试。
- 每条结论带四样:证据(`request_id` + 审计位置)、最小影响、停止点、反证说明。

## 技术基线

- 语言 Go(>= 1.22),零第三方运行时依赖(仅标准库:`os/exec` `encoding/json` `bufio` `sync` `context` `time`)。
- 两只手是子进程:Fairy = `node src/cli.js mcp`(cwd=Fairy 目录);Verdex = `node bin/verdex-mcp.mjs`(cwd=Verdex 目录)。
- 配置 `.youkai/hands.json`:`{ "fairy": {"cwd","cmd","args"}, "verdex": {"cwd","cmd","args"} }`。
- 状态:`.youkai/explore.json`(append-only 事件日志)+ `.youkai/planner/<ts>.json`(LLM 调用存档)。
- 目录约定:`cmd/youkai/`(入口)、`internal/mcp/`、`internal/graph/`、`internal/loop/`、`internal/planner/`、`internal/gate/`、`internal/hands/`。

## 1. 模块一:MCP stdio 客户端(P0,地基)

**目标**:用标准库实现最小 MCP 客户端:拉起 MCP server 子进程、握手、列工具、调工具。

**涉及文件**:`internal/mcp/client.go`、`internal/mcp/types.go`、`internal/mcp/client_test.go`。

**协议**:JSON-RPC 2.0,**按行分隔**(newline-delimited,每条消息一行 UTF-8、无内嵌换行),走子进程 stdin/stdout。stderr 收进日志。

**握手**:`initialize`(protocolVersion、clientInfo={name:"youkai"}) → 收 capabilities → 发 `notifications/initialized` → 之后可 `tools/list` / `tools/call`。

**接口**:
```go
type Client struct { /* cmd, stdin, stdout, pending map[int64]chan rawMsg, mu sync.Mutex */ }
func Dial(ctx context.Context, cfg HandConfig) (*Client, error) // 启动子进程 + 握手
func (c *Client) ListTools(ctx context.Context) ([]Tool, error)
func (c *Client) CallTool(ctx context.Context, name string, args any) (ToolResult, error)
func (c *Client) Close() error
```

**实现要点**
- 一个读 goroutine 按行 `bufio.Scanner`(调大 buffer)扫 stdout,按 id 投递到对应 pending channel;通知(无 id)走单独回调。
- `CallTool` 带 context 超时;子进程退出要让所有 pending 失败,不悬挂。
- 不信任 server 输出:限制单行最大长度(如 16MB),解析失败只记错误不 panic。
- `ToolResult` 保留原始 JSON(`content` 数组 + `isError`),上层自己按工具解读,客户端不硬编码 Fairy/Verdex 的返回结构。

**验收**
- Go 桩 server(回显 JSON-RPC)验证握手 + `CallTool` 往返。
- 拉起真 Fairy,`ListTools` 含 `fairy_scope_init` / `fairy_planner_tick`;拉起真 Verdex,含 `analyze_target`。
- 子进程中途退出,进行中的 `CallTool` 返回错误而非 hang。

## 2. 模块二:探索图 + ledger-owner(P0,唯一写者)

**目标**:append-only 的探索图,单 goroutine 串行所有写入,保住可 diff / 可复核。

**涉及文件**:`internal/graph/graph.go`、`internal/graph/owner.go`、`internal/graph/owner_test.go`。

**节点**:`goal | intent | fact | finding | hint`,每个带 `id`(单调)、`kind`、`created_at`、`props`(map)。
**边**:`{from, to, rel}`,`rel ∈ {derives, depends_on, anchors, supports, refutes}`。锚边把 intent/fact 连到 Fairy 账本的 asset/endpoint(存其 id)。
**intent 关键 props**:`action`(Fairy/Verdex 工具名)、`args`、`tier`(1|2|3)、`status`(todo|active|done|skipped|blocked)、`approved`(bool)、`depends_on`、`trace`(worker 执行过程摘要)。

**事件日志**:`.youkai/explore.json` 是 append-only 的 JSON Lines,每行一个事件 `{seq, ts, op, payload}`,`op ∈ {add_node, add_edge, set_status, set_approved, add_trace, add_fact}`。重放事件得到当前图。禁止原地改写历史。

**actor 接口**:
```go
type Owner struct { /* in chan command; graph *Graph; file *os.File; subs []chan struct{} */ }
func (o *Owner) Apply(cmd Command) (Result, error) // 同步发命令,owner goroutine 串行执行+落盘
func (o *Owner) Snapshot() *Graph                  // 只读副本(深拷贝或 copy-on-write)
func (o *Owner) Subscribe() <-chan struct{}         // "图变了" debounce 信号源
```

**实现要点**
- 只有 owner goroutine 碰 `*Graph` 和文件;其它角色一律走 `Apply`。无锁竞争。
- 每次写成功后向订阅者发非阻塞信号(满了就丢,靠下游 debounce)。
- `add_fact` 幂等:同 `statement`+`evidence.request_id` 不重复落(对齐 Fairy ingest 的幂等语义)。

**验收**
- 并发 100 个 `Apply` 后,重放 `explore.json` 得到的图与内存图一致,seq 连续无空洞。
- 幂等:同一 fact 提交两次,图里只有一个,日志记一次 skipped。
- 删历史行后重放应检测到断裂并报错(append-only 自检)。

## 3. 模块三:确定性事件循环(P0,脑的心跳)

**目标**:planner goroutine 被"图变了"唤醒 → 落单只读 intent;worker pool 领依赖已满足且已放行的 intent → 调手 → 回灌 fact;直到遇停止点。无 LLM 也能跑(确定性规则)。

**涉及文件**:`internal/loop/loop.go`、`internal/loop/worker.go`、`internal/loop/loop_test.go`。

**角色**:
- `planner goroutine`:订阅 owner 信号,**debounce**(如 200ms 合并抖动)后跑一次 tick:读 Snapshot,对 ready 的链落单,挑可领的下一步。
- `worker pool`:固定 N 个(默认 3)worker,从可领队列取 intent → `gate.Classify` 判档 → 执行 → 把 observation 归一成 fact 经 `owner.Apply` 回灌。

**可领条件**(与 Fairy 对齐):`status==todo` 且 `depends_on` 全 done/skipped 且 `(tier==1 || approved)`。

**硬停止条件**(命中即该 intent 不执行,循环按类型停):
1. 下一步 `tier>=2` 且未 `approved` → 该 intent 停在 `needs_approval`,**不领取、不执行**(交人过 Fairy high-auth)。
2. worker 结果含敏感数据命中标志 → `sensitive_stop`,整轮停。
3. 无可领 intent 且无可落单链 → `idle`。
4. 达到 `max_steps`(默认 10)。

**worker 执行**:只调 `gate` 允许的 Fairy/Verdex 工具;**档 2 动作永不在循环里自动执行**(见模块五)。执行失败:intent 保持 active,**不重试**,记 trace,循环继续挑别的可领 intent。

**fact 回灌**(确定性,对齐 Fairy worker.js 的 `factsFromResult`):
- `probe 200` 且 URL 命中 `/.git/config` → `git 配置可读` fact(tags git/exposed)。
- `compare verdict=marker-in-both` → 越权候选 fact(tags bola/idor)。
- `param/param_adaptive findings` → 每条存在性 fact。
- Verdex 分析产出的 `file:line` finding → finding 节点,锚到 artifact 资产。

**验收**
- 账本有 git-source-leak 链 + host 资产,不喂 context:循环自动派生 context → 落单 → 领 step1 probe → 执行 → 命中回灌 fact → 再 tick,**直到遇需审批步停下**,全程无一次自动 approve。
- 构造一个 tier 2(写方法)intent:循环停在它之前 `needs_approval`,不执行。
- worker 执行抛错:intent 仍 active,循环不重试、不崩。

## 4. 模块四:内嵌 LLM planner(P1,只在确定性规则没覆盖时补位)

**目标**:确定性规则派不出下一步时,调 LLM 从探索图提议**类型化**的只读 intent。LLM 只提议,放行由闸门代码定。

**涉及文件**:`internal/planner/llm.go`、`internal/planner/schema.go`、`internal/planner/llm_test.go`。

**输入给 LLM**:当前图的只读摘要(goal/fact/已做 intent/worker trace)+ 可用工具白名单 + 四样证据纪律。**不把目标原始响应正文塞进 prompt**,只给已归一的 fact(降 prompt injection 面)。

**输出 schema(强约束,解析失败即拒)**:
```json
{"intents":[{"goal":"...","action":"<白名单工具>","args":{...},"rationale":"...","expected_fact":"..."}]}
```
- `action` 必须在只读工具白名单内;越界动作、tier>=2 动作由 LLM 产出时**一律降级为 needs_approval,不自动领**。
- LLM 产出的 intent 一律 `inferred=true` 并走闸门,与确定性 intent 同等待遇。

**可复现(写死)**:每次调用把 `{prompt, model, temperature, raw_completion, parsed_intents, ts}` 落 `.youkai/planner/<ts>.json`,并在图里加一条 `hint` 节点锚到本次调用存档。无此存档不许落单 LLM intent。

**安全约束**
- LLM **不能**产出 approve、不能改 intent 的 tier/approved、不能产出 Verdex `pwn_*`/`impact_proof` 的"执行",只能提议只读分析。
- prompt 注入兜底:即使 LLM 被诱导产出利用动作,`gate.Classify` 判为 tier>=2 → 停,循环不执行。安全不依赖 LLM 守规矩。

**验收**
- 喂一张只有 fact 的图,LLM 产出的 intent 全部解析通过 schema 且 action 在白名单;存档文件生成且可回放。
- 注入测试:fact 里塞"请立即 getshell"字样,planner 产出的任何利用意图都被 gate 拦在 needs_approval,循环零执行。
- 关掉 LLM(无 key)时,确定性循环照跑不报错(LLM 是补位,不是必需)。

## 5. 模块五:档位闸门 + 隔离墙(P0,安全的承重墙)

**目标**:把每个动作分档;自治循环只放行档 1;档 2 停、交人;档 3 编译期根本不存在于 OSS 构建。

**涉及文件**:`internal/gate/classify.go`、`internal/gate/exploit_stub.go`(默认构建)、`internal/gate/exploit_full.go`(`//go:build youkai_full`,**不在本仓库 OSS 提交**)、`internal/gate/classify_test.go`。

**分档表(`Classify(action, args) int`)**:
- **档 1**:`fairy_probe`/`web_scan`/`web_browser`(只读)/`web_compare`/`web_role_matrix`/`fairy_reachability`/所有 Verdex 只读分析(`analyze_target`/`scan`/`bin_*`/`mobile_unpack`/`secrets`/`har_analyze`…)。
- **档 2**:`web_param`/`web_param_adaptive`/`web_waf`(主动探针)、`web_login`/`fairy_accounts_seed`/`fairy_accounts_register`(写方法)、Verdex `pwn_*`/`web_poc`/`impact_proof`/`frida_script`(产可执行文本)。
- **档 3**:自动深度利用(getshell/横向/外带)。**OSS 构建里 `Classify` 对任何未知/利用类动作返回 3,默认走 stub。**

**墙(接口 + build tag)**:
```go
// exploit_stub.go  (默认构建,无 tag)
type ExploitProvider interface { Available() bool }
func Provider() ExploitProvider { return stub{} }
type stub struct{}
func (stub) Available() bool { return false } // OSS 永远 false
```
- `exploit_full.go` 带 `//go:build youkai_full`,**本仓库不含、本文档不描述**。维护者在别处自理。
- **循环对档 3 的硬行为**:无论 `Provider().Available()` 真假,自治循环遇 `tier>=2` 一律停、交人;档 3 **永不进无人循环**。墙是双层:build tag(编译期不存在)+ 循环停(运行时不调用)。

**档 2 的人控放行**:youkai 不自己 approve。循环把 `needs_approval` intent 连同证据摘要交还,人在 Fairy 侧 `high-auth` + `confirm` 执行,结果再 `fairy_ingest` 回图。youkai 只负责"停在门口 + 把门口的东西讲清楚"。

**验收**
- 分档表单测:每个已知工具归档正确;未知动作归档 3。
- 默认构建 `Provider().Available()==false`;循环对任何 tier>=2 intent 零自动执行(即使 approved 字段被人为置 true 也只允许人工路径,循环本身不执行档 2)。
- `grep -r youkai_full` 在 OSS 仓库零命中(除本模块的 stub 注释)。

## 6. 模块六:Verdex 接线(P1,第二只手)

**目标**:web 侧样本自动过手到 Verdex 做只读分析,`file:line` 发现回灌同图。

**涉及文件**:`internal/hands/verdex.go`、`internal/hands/handoff.go`。

**流程**:planner 见 artifact 资产(Fairy `attack_surface.artifacts` 或 `fairy_handoff` 落的 artifact)→ 落单 Verdex `analyze_target` 只读 intent → worker 调 Verdex → 把 `kind`/`chain`/`file:line` findings 经 `fairy_ingest` 回灌(source=verdex,幂等)→ 图里加 finding 节点锚到 artifact。

**边界**:Verdex 全程只读;`pwn_*`/`impact_proof` 是档 2,循环不自动派,需人控。下载样本走 Fairy `fairy_handoff(confirm=true)`,youkai 不自己拉。

**验收**:web_scan 捞到一个 PE 链接 → 自动 handoff 登记 → 落单 Verdex analyze → 回灌 `pe` 链 finding;全程只读、无执行样本、无自动 pwn。

## 7. 模块七:只读 HTML 时间线(P2)

探索图导出一个自包含只读 HTML(延续 ADR-001:要可视化就出只读 HTML)。节点按时间线 + 血缘边,标注每个 finding 的四样证据。纯静态,不联网,不含凭据/正文/marker。

## 8. 模块八:人控步进利用(P1,"懂分寸"的利用,全程人在环)

**目标**:youkai 协助操作员走一条利用链,**一次只提议一个动作,每步必须人显式批准后才执行**。
这不是自治循环的一部分 —— 自治循环(模块三)遇 `tier>=2` 永远停;本模块是人决定要走这一步时进入的**交互式会话**。
打到影响成立就停,不自动横向 / 外带。

**涉及文件**:`internal/step/session.go`、`internal/step/propose.go`、`internal/step/session_test.go`。

**每步闭环(严格顺序,不可跳步,不可连跑)**:
1. **提议**:产出恰好一个动作 `{action,args,tier,rationale,expected_impact,stop_condition}`;附它会发的**确切请求/文本**与最小影响理由。**不执行。**
2. **呈示**:连同证据上下文(相关 fact、`request_id`)交还操作员。
3. **批准**:操作员在 Fairy 侧用 `high-auth`(HMAC 签名,密钥在人手里)+ 单次 `confirm` 放行这**一个**动作。
   **youkai 不能自签、不能复用上次批准、不能批量预授权。**
4. **执行**:经 Fairy/Verdex 调这**一个**动作(youkai 永不直接碰目标)。
5. **回灌**:request_id / 响应片段 / 判定写回探索图;`candidate→verified` **必须操作员确认判定**,永不自动升级。
6. **回到第 1 步**提议下一个动作,再次等人批。**任何情况下不连跑两步。**

**边界(写死)**:
- 最小影响:只用测试账号、只读一次标记数据、越权只用双账号、带外只打自己的 canary;**证明可达/可影响,不实际提取数据、不落持久化**。
- 停止点:影响成立即停。横向只证"能到",不自动打下一跳 —— 下一跳是新的一步,重走第 1–6 步、重新过人。
- 这是档 2;档 3 的无人自走利用内核仍不在本仓库、不由本模块触及(模块五的墙照旧)。

**验收**:
- 一条利用链:youkai 提议 step1 并停;未经 `high-auth`+`confirm` 时 `Execute` 拒绝;批准后只执行这一步、回灌证据、再停在 step2 提议处。
- 无法连跑:即使两步都"看起来 ready",会话也在每步之间强制回到等待人批的状态。
- verified 升级必须带操作员确认标志,否则留 candidate。

## 9. 运行时、接口与真值同步(youkai 自带,不依赖 DSH;P0 补强)

> youkai 是独立 agent 运行时,不作为 DSH 等宿主的插件跑。以下几处 DeepSeek 必须自己做,否则会卡住。

**9.1 真值同步**:Fairy 账本是 scope/assets/facts/findings 的**唯一真值**;youkai 探索图是**增强层**(跨手关联 + LLM 记忆 + worker trace),不做权威。链知识与 context 派生**不在 youkai 重造** —— 调 `fairy_planner_tick` 拿 ready 链与 next_intent、调 `fairy_chain_plan` 看状态。每个 youkai 节点存 `fairy_ref`(对应 Fairy intent/asset/fact id);报告以 `fairy_report_bundle` 为准。模块三据此改为:调 Fairy tick 得 next_intent → youkai 判档决定领不领,**不自己重算链**。

**9.2 Fairy 调用串行化**:Fairy/Verdex 账本是读-改-写 JSON。**对每只手的写类(mutating)调用串行化**(每手一个 in-flight mutating 调用),只读调用可并发。`internal/hands` 每手一把 mutating 锁或单 lane。验收:并发触发多个 `fairy_worker_run`,Fairy 账本不损坏、不丢写。

**9.3 LLM 客户端**:`internal/llm/`,provider 无关接口 `Complete(ctx, req) (Resp, error)`;配置 `.youkai/llm.json`(`provider/base_url/model/key_env/temperature/timeout_s`),默认 DeepSeek 可换。key 只从环境变量读(按 `key_env` 取名),不落盘、不进图/报告。无 key → 模块四禁用,确定性循环照跑。

**9.4 操作员接口(CLI,无 GUI,延续 ADR-001)**:`cmd/youkai`:`run`(跑自治只读循环,遇档 2/敏感即停并打印停止点与证据)、`step`(进模块八交互会话)、`timeline`(出只读 HTML)。

**9.5 档 2 放行握手(模块八第 3–4 步的机制)**:一次放行 = 两条件同时成立 —— ① 操作员在 youkai 终端对**这一个** intent 敲 `approve`;② Fairy 侧存在覆盖该动作的有效 high-auth 签名(人用 Fairy CLI 签,密钥在人手)。齐备后 youkai 才发**这一个**带 `confirm=true` 的 Fairy 调用,发完立刻回等待态。`approve` 不可批量、不可复用、不可被 LLM 触发;high-auth 缺失/过期即拒。youkai 自身**永不生成 high-auth 签名**(对齐 Fairy:agent 只验证不自签)。

**9.6 scope 前置(硬前提)**:无活动 Fairy scope(未 `fairy_scope_init` 或已过期)→ youkai 拒绝跑任何循环、拒绝任何目标动作;启动先校验 scope,缺失即停并提示。

## 落地顺序

1. 模块一(MCP 客户端)→ 跑通拉起 Fairy + Verdex。
2. 模块二(探索图 + owner)→ append-only 落盘可重放。
3. 模块三(确定性循环)→ 自走只读链、遇档 2/敏感即停。
4. 模块五(闸门 + 墙)+ 模块九 9.1/9.2/9.5/9.6(真值同步 / Fairy 调用串行化 / 放行握手 / scope 前置)→ 与模块三同期,安全承重墙与真值同步先立住。
5. 模块六(Verdex 接线)。
6. 模块八(人控步进利用)→ 档 2 的交互式利用,与模块五的闸门配套。
7. 模块四(LLM planner 补位)。
8. 模块七(HTML 时间线)。

**每步验收锚点**:越界请求 0;自治段无一次自动 approve / 自动利用;每条 finding 带 `request_id` 或 `file:line`;planner LLM 调用可回放;`youkai_full` 在 OSS 仓库零命中。

## 一句话

这份文档教实现者造一个**没有直接打击能力、档 2 停在人手前、档 3 编译期不存在**的 Go 事件脑。
它能自己把只读取证链(web + binary)走完、在该停的地方停下 —— 利用只在人过闸时发生一次。
