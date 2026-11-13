# youkai

**一个没有直接打击能力的脑。** youkai 是独立的 Go 事件引擎,通过 MCP(stdio)驱动两只"手"——
[Fairy](https://github.com/) (web)与 Verdex(binary)——把**只读取证链**自己走完,
在该停的地方停下,利用只在人过闸时发生一次。

> ADR-002 的一句话:ARTEX 证明"AI 能自己跑到 `prove_goal` 并因此出事";
> youkai 要证明"一个没有直接打击能力的脑,能自己把只读取证链走完、在该停的地方停下,
> 利用只在人过闸时发生一次"。

## 它是什么 / 不是什么

| 是 | 不是 |
|---|---|
| 常驻型事件循环(ledger-owner + planner + worker pool) | 平台、UI、守护进程、数据库 |
| 只读取证的自主编排 | 自动利用 / 横向 / 外带(OSS 版不存在) |
| 每条结论带 `request_id` + 审计位置 | 会自己发目标请求的工具 |
| 档 2 停在人手前,把"门口的东西"讲清楚 | 会自己 approve / 自己升级 finding 的系统 |

**youkai 永不自己发目标请求。** 每个碰目标的动作都是一次 Fairy/Verdex 调用,
由那只手重新校验 scope + 审计。这让"比 ARTEX 安全"是构造上成立的,不靠自觉。

## 快速开始

```powershell
# 0) Go >= 1.22(本机装在 D:\tools\go)
go build -o youkai.exe ./cmd/youkai

# 1) 写两只手的路径
.\youkai.exe init --fairy-dir D:\fairy_fairy --verdex-dir "D:\漏洞挖掘工作台"

# 2) 体检:握手 + 工具清单 + 隔离墙状态
.\youkai.exe hands

# 3) 让人在 Fairy 侧先立授权护照(youkai 不做这件事,见下文"分档")
node scripts\mcp-call.cjs D:\fairy_fairy "src/cli.js mcp" fairy_scope_init "@scope.json"

# 4) 跑一轮有界循环(档 1)
.\youkai.exe run --project D:\lab\demo --seed http://127.0.0.1:8080

# 5) 看它停在哪
.\youkai.exe graph
.\youkai.exe html --out timeline.html
```

`run` 的退出码就是结论:`0` 跑完/空转,`10` **停在 needs_approval**,`11` 命中敏感数据停下。

### 人控步进(档 2,一次一个动作)

```powershell
.\youkai.exe step propose --next --project D:\lab\demo
#   → 打印 exact request / min impact / stop condition / evidence / fingerprint,不执行

.\youkai.exe step execute                       # 拒绝:没有操作员批准
.\youkai.exe step approve --fingerprint sha256:... --operator alice `
      --basis "self-hosted lab, ticket 42" --confirm
.\youkai.exe step execute                       # 只执行这一个动作,approval 立即消费
.\youkai.exe step execute                       # 再拒绝:上一步的批准不能复用
```

## 架构

```
cmd/youkai            入口:init / hands / run / graph / html / intent / step
internal/mcp          手搓 JSON-RPC over stdio(握手、按行分发、超时、进程退出不悬挂)
internal/graph        append-only 探索图 + 唯一写者 owner goroutine(重放即真相)
internal/gate         分档表 + 隔离墙(OSS 构建 Provider().Available() == false)
internal/loop         确定性事件循环 + worker pool + facts 归一 + 敏感数据即停
internal/planner      可选 LLM planner(只提议、全量存档、白名单 + 分档双重拒)
internal/step         人控步进会话(指纹绑定的单次批准,不可复用、不可批量)
internal/hands        Fairy / Verdex 接线、工具路由、handoff、账本回灌
internal/result       读一只手返回的证据信封(request_id 等,一处读法)
internal/wording      "四种证据"的单一措辞来源(报告与审批提示不会互相矛盾)
internal/timeline     自包含只读 HTML 时间线(无脚本、无联网、脱敏)
```

**写死的不变量,以及它在代码里的落点**

| 不变量 | 落点 |
|---|---|
| 只跑档 1 | `gate.Tier.AutonomousOK()`;`loop.choose` 用 `max(gate, 声明 tier)`;`loop.execOne` 再查一次 |
| 档 2 停、交人 | `loop.park` + `Pending`(exact request / min impact / stop condition / evidence) |
| 永不自动 approve | `gate` 把 `ledger_advance(action=approve)` 判为 tier 3;CLI 无 `intent approve` 子命令 |
| 永不自动利用 | `gate.Provider().Available()==false` 编译期;`//go:build !youkai_full`;`step.Propose` 拒 tier 3 |
| 永不把 candidate 改 verified | `worker` 只写 `status=candidate`;`step.Verdict` 必须 `confirmed && note != ""` |
| 失败不重试 | `loop.fail` 只留 trace,intent 保持 active(不可再领) |
| 每结论带证据 | `loop.facts` 归一为 statement + `request_id`/`audit_path`;`result.RequestID` 统一读取 |
| LLM 只提议 | `planner/schema.go` 白名单 + tier 双重拒;`loop.propose` 拒绝无存档提议 |

## 与 DEVPLAN-v0.1 的已知差异

诚实列出,不和稀泥:

1. **debounce 不是活动机制。** `loop.Run` 是同步有界循环:每批执行完立刻重 tick,
   不需要合并抖动。`--debounce` 旗标保留给将来的 watcher 模式,当前对单次 run 无行为影响。
   (DEVPLAN 模块三设想的是常驻 planner goroutine + 订阅信号;youkai 的 owner 已有
   `Subscribe()`,但循环是"调一次跑一段"的形态,与 ADR-002 的"有界循环,不是常驻服务"一致。)
2. **资产顶点是新增节点类型。** DEVPLAN 的节点集是 goal/intent/fact/finding/hint,
   但"锚边指向账本 asset"需要一个真实端点。youkai 增加 `asset`(kind=host/surface/artifact),
   anchors 边指向它;图谱因此自包含、可离线重放。
3. **LLM 的越界提议是"丢弃 + 存档",不是"落成 needs_approval"。** 若按后者实现,
   一段可控的目标文本(经 fact 进入 prompt)就能让自主循环永久卡在 needs_approval —— 
   那是对脑的拒绝服务。丢弃保证更强:注入不能导致执行,**也不能改变循环控制流**,
   而拒绝理由原文留在 `.youkai/planner/<ts>.json` 里供审计。
4. **`OpSkipped` 是文档 op 集合的增项。** 幂等拒绝必须在日志里可见,否则"拒绝"和
   "写丢了"无法区分。
5. **`fairy_handoff` 分档按参数走。** `path=` 登记是档 1;`url=+confirm=true` 下载是档 2
   (youkai 不自己拉样本)。

## 验证

```
go vet ./...        clean
go test ./...       67 tests, all pass
```

真机验收(2026-11-13,本机 Fairy v0.1.0 / Verdex v0.2.0):

- `youkai hands` → fairy 39 tools / verdex 35 tools,协议 `2024-11-05`,含
  `fairy_scope_init` `fairy_planner_tick` `web_probe` `fairy_ingest` `analyze_target`。
- `youkai run --seed http://127.0.0.1:18080` → 自动落单并执行 `web_probe`(命中
  `/.git/config` 200 → 回灌 `git 配置可读` fact)+ `web_scan`;
  `web_scan` 发现参数反射 → 派生 `web_param`(档 2)→ **停**,`exit 10`,并打印四种证据。
- `youkai step propose --next` → 出提议与指纹;`step execute` 无批准被拒;
  `approve` 无 `--confirm` 被拒;错误指纹被拒;批准后 `execute` 只跑一次,再次 `execute` 被拒。
- `youkai html` → 自包含页面(32 节点卡片、11 条 finding 的四段证据、无 `<script>`、无外链)。

`scripts/acceptance.ps1` 可整套重放(会起本地靶场、写 scope、跑循环并断言退出码)。

## 红线

只对**授权目标**动手:CTF、自建靶场、你拥有或被明确授权的系统。
youkai 复用 Fairy 的 scope 护照;没有护照,`web_*` 一个请求都发不出去。
档 3(自动深度利用)不在本仓库、不由本仓库实现、也没有可翻的运行时开关。
