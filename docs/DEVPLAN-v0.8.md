# DEVPLAN-v0.8:工程化加固(CI / 许可合规 / 基准 / 发布就绪)

> 交付对象:实现者(DeepSeek)。配 ADR-004、所有 IMPL-STATUS、README 读。
> 目标:**不加功能**,把 v0.1→v0.7 的成果巩固成**可发布状态** —— CI 挡回归、许可合规、可复现基准、安全不变量进自动化门禁。

## 0. 现状盘点(缺口)

- **无 CI**:没有 `.github/workflows`。每次改动靠人跑 `go test`,回归可能漏网(v0.1 那次 migrate 死锁就是人跑才发现)。
- **无许可文件**:youkai 自称 MIT(package 语义、README「许可与血统」),但仓库**没有顶层 `LICENSE`** —— 法律硬伤,吸收了 Fairy/Verdex(MIT)代码更需把许可链写清。
- **无 SECURITY / CONTRIBUTING**:一个安全工具没有漏洞上报渠道与负责任使用声明,不合适。
- **无 bench**:STRATEGY/COMPETITIVE 都强调"唯一可信的数字来自本机靶场基准",但 youkai 侧还没有 bench(Fairy 有 `bench/`)。
- **安全不变量散落在各包测试**:`TestNoEgressOutsideTheGuard`、档 3 墙、PG 触发器都在,但没有一个"安全门禁"把它们聚合成 CI 必过项。

## 0.5 不可动摇(本轮同样适用)

- 不改任何运行时行为、不加能力、不动档位墙:纯工程化。
- CI 里的 PostgreSQL 用临时实例,**不碰** `.pgsql/`(操作员的真实账本数据目录)。
- 许可:youkai = MIT;移植自 Fairy/Verdex(均 MIT)要在 LICENSE/NOTICE 保留其版权;只借 ARTEX/norma(AGPL)思想、不含其代码,这条要在 NOTICE 写明。
- bench 只对**本机靶场**,结论不外推(延续 COMPETITIVE 的诚实口径)。

## 1. CI 门禁 `.github/workflows/ci.yml`(P0)

**目标**:每次 push / PR 自动跑 build + vet + 全量测试(含 PG 相关),红就挡。

**要点**:
- 跑在 Linux runner;`services:` 起一个 `postgres:16` 容器,导出 `YOUKAI_TEST_DSN` 指向它(**不用 `.pgsql/`**)。
- 步骤:`go build ./...` → `go vet ./...` → `go test ./... -count=1`(migrate 的 advisory lock 已保证并行安全)。
- Go 版本矩阵:1.22 + stable(对齐 `go.mod`)。
- gofmt 检查:`gofmt -l .` 非空即失败。

**验收**:CI 在干净 checkout 上全绿;故意引入一个失败测试 → CI 红。

## 2. 安全不变量门禁 `.github/workflows/invariants.yml`(P0,youkai 的特色)

**目标**:把"安全靠构造"的那几条做成**独立的、必过的** CI 作业,名字显眼,一眼看出底线没破。

**聚合这些已存在的检查,缺一即红**:
- 唯一发包通道:`go test ./internal/discipline -run TestNoEgressOutsideTheGuard`。
- 报告纯投影:`go test ./internal/discipline -run TestReportPackageCannotReachTheNetwork`。
- 档 3 墙:`grep -rn "youkai_full" --include=*.go .` 只允许命中 `internal/gate/exploit_stub.go` 一处;默认构建 `gate.Provider().Available()==false`(加一个小测试断言)。
- 浏览器不开第二出口:`grep -rn "Network.setCookie\|setExtraHTTPHeaders" internal/ --include=*.go` 零命中。
- PG 触发器存在:对测试库查 `information_schema.triggers`,断言 `audit_log` / `findings` / `report_snapshots` 的 append-only/护栏触发器都在。

**验收**:门禁作业全绿;删掉任一触发器 / 加一个绕过 Guard 的 http 调用 → 对应断言红。

## 3. 许可与合规文件(P0,法律硬伤)

**目标**:补齐 `LICENSE` / `NOTICE` / `SECURITY.md` / `CONTRIBUTING.md`。

- **LICENSE**:MIT,youkai 版权行。
- **NOTICE**:写明 —— 原生移植 Fairy、Verdex 的能力(均 MIT,同作者),保留其版权;平台/事件架构只借 ARTEX(RuoJi6/ARTEX)与 norma 的**思想**,**不含其代码**(它们是 AGPL-3.0)。
- **SECURITY.md**:对标 Verdex 的口径 —— youkai 的红线(授权目标、只读默认、档 2 人批、档 3 不在仓库);漏洞上报渠道(私密);**什么算 youkai 漏洞**(绕过 Guard/scope、未审计发包、凭据泄漏、绕过档位墙、PG 护栏失效)vs **不算**(用户自己授权目标里的漏洞、要求加攻击能力)。
- **CONTRIBUTING.md**:构建/测试/起 PG 的步骤、提交前必过 CI 两个门禁、新增能力必须先挂 `discipline.Guard` 且进 `gate` 分档表、不得引入第二发包通道、档 3 相关 PR 不接受。

**验收**:四个文件就位;SECURITY 明确上报渠道与"是/不是 youkai 漏洞";NOTICE 许可链清楚。

## 4. 本机靶场基准 `bench/`(P1)

**目标**:可复现的本机靶场基准,产出 recall / precision / 每发现请求成本 / 越界请求数,口径对齐 COMPETITIVE。

**要点**:
- 复用 `scripts/lab-target.py`(已有 git 泄露/反射/BOLA/CAPTCHA 等);定义 ground truth(该靶场已知应检出的条目)。
- `bench/run`(Go 或脚本):建临时作业 + scope → 跑自治只读链 → 收集发现 → 对 ground truth 算 recall/precision → 打印请求成本与越界计数(必须 0)。
- 输出 `bench/results/<date>.json` + 一行摘要;**只声明本机靶场,不外推**。

**验收**:`bench` 在本机靶场跑出非空数字;越界请求=0 是硬断言;结果可重放(同靶场数字稳定)。

## 5. 文档整理(P2)

- README 加「状态」徽章段:当前 v0.7、CI 状态、两个安全门禁。
- docs 加一个 `INDEX.md`:按 ADR(决策)/ DEVPLAN(规格)/ IMPL-STATUS(进度)/ E2E / GAPS 分类列出,标注哪些已 superseded(如 IMPL-STATUS-v0.1)。
- 核对 README 与当前实现一致(端口 8799、能力清单含 v0.6 登录态、v0.7 trace)。

**验收**:INDEX 覆盖全部 docs 且标注 superseded;README 无过时信息。

## 落地顺序

1. 模块三(许可合规)—— 法律硬伤先补,零风险。
2. 模块一(CI)+ 模块二(安全门禁)—— 挡回归的网先张开。
3. 模块四(bench)。
4. 模块五(文档整理)。

**每步验收锚点**:CI 在干净库全绿且能挡回归;安全门禁把 5 条不变量变成必过项,破坏任一即红;LICENSE/NOTICE 许可链清楚;bench 越界=0 且可复现;不改任何运行时行为。

## 一句话

v0.1→v0.7 把 youkai 建起来了;v0.8 给它上锁 ——
让"安全靠构造"不只是写在代码里,而是每次 push 都被 CI 逼着证明一遍。
