# IMPL-STATUS v0.8 — 工程化加固(CI / 许可 / 基准 / 发布就绪)

> 日期:2026-11-14 · 承接 DEVPLAN-v0.8 · `go test ./...` 全绿 · `scripts/acceptance-v02.ps1` 全通过
> 新增:`LICENSE` / `NOTICE` / `SECURITY.md` / `CONTRIBUTING.md`、
> `.github/workflows/{ci,invariants}.yml`、`bench/`、`docs/INDEX.md`。
> **未改任何运行时行为**(除了两处真 bug 修复,见末节)。

## 一句话

v0.1→v0.7 把 youkai 建起来;v0.8 给它上锁 —— 让"安全靠构造"从一句话变成每次 push 都被逼着证明一遍的作业。

## 一 · 许可与合规(先补的法律硬伤)

| 文件 | 内容 |
|---|---|
| `LICENSE` | MIT,youkai 版权行 |
| `NOTICE` | 移植自 Fairy / Verdex(均 MIT,同作者),保留其版权;**只借 ARTEX / norma(AGPL-3.0)的思想,不含代码**,并写明"若你认为不是,请提 issue,下个版本前移除或改许可" |
| `SECURITY.md` | 七条不变量 ↔ "破坏它长什么样"的对照表;什么**算** youkai 漏洞(绕过 Guard/scope、未审计发包、凭据泄漏、绕档位墙、报告不可投影、DB 护栏失效)vs 什么**不算**(目标里的漏洞、要求加攻击能力、模型提议本身) |
| `CONTRIBUTING.md` | 构建/测试/起 PG;新增能力的五条不可谈判项(过 Guard、进 gate 分档、档 2 全套门、证据可引用、输出无秘密);明确不接受的东西(第二发包通道、批量放行、档 3 代码) |

## 二 · CI(`.github/workflows/ci.yml`)

- Linux runner + `postgres:16` service(临时实例,**不碰 `.pgsql/`**)。
- Go 版本**矩阵 1.22 + stable**(对齐 `go.mod`)。
- 步骤:`gofmt -l .`(非空即失败)→ `go build` → `go vet` → `go test ./... -count=1`。
- 额外一条:构建二进制后**不带数据库启动必须失败**(`-dsn ""` → 非零退出),防止有人把"没有账本也能跑"改回来。

本地等价验证:上述命令在本机全绿(`gofmt -l .` 空、vet 干净、182 测试通过)。

## 三 · 安全门禁(`.github/workflows/invariants.yml`,5 个独立作业)

| 作业名 | 内容 |
|---|---|
| `invariant: one egress path (the guard)` | `TestNoEgressOutsideTheGuard` |
| `invariant: the report cannot reach the target` | `TestReportPackageCannotReachTheNetwork` |
| `invariant: tier 3 is not in this build` | `youkai_full` 只允许出现在 `internal/gate/exploit_stub.go`(逐行过滤后仍超界即红)+ `TestExploitProviderIsStubbed` |
| `invariant: the browser opens no second exit` | `grep "Network.setCookie\|setExtraHTTPHeaders\|Storage.setCookies" internal/` 零命中 + 两个真机浏览器测试 |
| `invariant: database guardrails exist` | 起一次服务应用 schema,再查 `pg_trigger`:四个触发器必须都在;随后跑三个触发器行为测试 |

**为什么独立成作业**:名字就是承诺。哪天红了一个,不用读日志也知道死的是哪条。

> 顺带修的:浏览器注入的注释里写着 `Network.setCookie`,会误触第 4 条门禁。
> 已改成不含该字面量的说法 —— 注释解释"为什么不用它",但门禁必须能干净地 grep。

## 四 · 本机靶场基准(`bench/`)

```
go run ./bench -port 18088 -max-steps 12
youkai bench · http://127.0.0.1:18088 · steps=12
  recall 1.000  precision 1.000  findings 7  requests 10 (blocked 0)  cost/finding 1.43
  ok git-exposure / reflection / header-csp / header-xfo / header-xcto / header-referrer / version
  stop: needs_approval — 1 intent(s) need a human: param
```

- **进程内**跑真引擎 + 真 dispatcher:`bench` 里**没有 HTTP 客户端**,所以它自己也不会成为第二条出口
  (这正是 `TestNoEgressOutsideTheGuard` 要求的)。
- ground truth 来自**靶场源码**(不是上一次运行的输出);precision 只对得上 ground truth 的发现计真。
- **越界请求 = 0 是硬断言**:一旦出现 blocked 审计行,bench 非零退出。
- 口径写死:`bench/README.md` 明确"只测档 1 匿名只读链、只对这台机器的这个靶场、不外推"。
  档 2 要人批,伪造那两个条件的基准测的是另一个产品。

## 五 · 文档整理

- README 顶部加**状态段**(版本 / 测试 / CI / 安全门禁 / 许可 / 上报 / 索引)。
- 新增 `docs/INDEX.md`:按 ADR / DEVPLAN / IMPL-STATUS / 验证分类,**标注 superseded**
  (ADR-001、DEVPLAN-v0.1、IMPL-STATUS-v0.1/v0.2),并给出新人阅读顺序。
- 核对端口:`YOUKAI_ADDR` 默认其实是 `127.0.0.1:8787`,README 之前写成 8799。
  已改成"默认 8787(`start-youkai.cmd` 用 8799)",与实现一致。

## 顺带修掉的两个真 bug(基准第一次跑就暴露)

1. **引擎失败后把意图永久留成 `active`**。`fail()` 只写 trace 不写状态:没人再 claim 它,
   工作台也看不见,而指纹去重又不会重派 —— 一次瞬时失败就把整条链卡死。
   现在失败即 `blocked`(可见、不再被 claim),trace 写"marked blocked, not re-derived"。
   这和 v0.5 E2E 在 API 执行路径上修的是同一类问题,这次是引擎路径。
2. **基准自己把 scheme 猜错**:只给 `127.0.0.1:port` 的护照默认推 `https`,于是第一发就是 TLS 打到明文 HTTP 上。
   修法不是让引擎猜,而是让 bench **像 youkaid 一样把 seed URL 交给引擎**(`SeedURLs`),
   由带 scheme 的种子决定 surface。

## 与 DEVPLAN-v0.8 的差异 / 未做

- **CI 没有在 GitHub 上真跑过**(本机无远端)。workflows 已按可执行的命令写成,
  并在本机逐条验证了等价命令;第一次 push 到 GitHub 才能确认 runner 层面的细节
  (例如 ubuntu 上 Chrome 是否在场 —— 浏览器测试在没有 Chromium 时是 skip,不是失败)。
- **没有接 `go-licenses`/SBOM**:NOTICE 指向 `go-licenses report ./...`,但没把它做成 CI 步骤。
- **bench 是单次、单靶场**;没有做多轮统计(方差)、也没有做多靶场对照。
- **没有做发布产物**(goreleaser / 签名 / 版本注入):`youkai -version` 目前走 `api.Version` 常量。
