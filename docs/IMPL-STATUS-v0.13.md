# IMPL-STATUS v0.13 — 白盒源码分析(读代码指导测试)

> 日期:2026-11-15 · 承接 DEVPLAN-v0.13 · `go test ./...` 全绿、验收全过
> 新增:`internal/whitebox`(源码→路由/数据流/认证覆盖)、`hypotheses` 表、
> `code_ingest` 能力(档 1)、引擎的 `ruleWhiteboxProbe`、`GET …/hypotheses`。

## 一句话

youkai 现在能读你给的应用源码,画出"哪个入口的哪个参数可能通到哪个危险 sink"的**地图**;
然后自己按地图去外面敲一次门 —— 敲门声对上才算线索成立,对不上就老实地记成"未确认"。

## 一 · 源码接入与路由发现 `code_ingest`(档 1,纯本地)

- 能力:`code_ingest{path}`,读一个目录(不跟随出树、跳过 `node_modules/vendor/dist/build`,
  单文件 512 KiB / 4000 文件 / 400 路由 / 200 假设封顶)。
- 支持三栈:Express/Koa(JS)、Flask(Python)、Gin/Echo(Go);其余扩展点留在语言枚举里。
- 每条路由登记成 `code-endpoint` 资产:method、path、handler、`file:line`、**是否有认证**、
  框架名。这是让代码视角和网络视角能对上锚的地方。
- **零请求**:这个能力不建 Guard,因为它开的是文件不是套接字。

## 二 · source→sink 数据流 → 假设

- source:`req.query/params/body`、`request.args/form/values`、`c.Query/Param/PostForm`、
  `$_GET/POST`、`getParameter`。
- sink 八类:`sql-concat`、`rce`、`path`、`ssti`、`redirect`、`ssrf`、`deserialize`、`html-output`。
- 识别 sanitizer 并降噪:参数化查询(`?`/`$1` + 参数数组、`prepare`)、`parseInt`、`escape*`、
  `htmlspecialchars`、`shlex.quote` 等 —— 中间有这些就不产假设。
- 产出 `hypotheses` 表的一行:`{kind, entry, param, sink, path(file:line→sink), confidence:"code-only", note}`。
  **confidence 恒为 code-only**,note 里明写"启发式,可能误报"。

## 三 · 认证覆盖 → 越权假设

- 路由附近没有认证中间件/装饰器、且方法或路径像有状态(`POST/PUT/PATCH/DELETE` 或
  `admin/delete/update/pay/order…`)→ 产 `missing-authz` 假设。
- 文件里出现全局认证(`app.use(auth…)`、`@login_required`、`Use(AuthMiddleware())` 等)时**不产**,
  避免把"全局中间件保护的站"整站误报。

## 四 · 喂给引擎:线索 → 探测 → 候选

引擎新增 `ruleWhiteboxProbe`,每轮读 open 状态的线索:

| sink | 派生 | 档位 |
|---|---|---|
| `sql-concat` | `param{url, param, classes=[sqli], hypothesis_id}` | **档 2,停下点头** |
| `redirect` | `redirect_check{url, hypothesis_id}` | 档 1 |
| 其它(rce/path/ssti/ssrf/deserialize/html) | 不派生 | —— 没有安全的"存在性探测" |

探测跑完由 `ConfirmProbe` 结算线索:

- 命中(有真实发现)→ `candidate`,note 记下请求号;
- 没命中 → `unconfirmed`,note 写"代码看着可疑,但这次探测没有复现:不构成发现,仅记录"。

**两条执行路径共用同一个结算函数**:引擎自治跑的和人点头跑的,都走 `engine.ConfirmProbe`。

## 实测(本机靶场 + 一份合成源码)

```
code_ingest → 4 条线索
  [open] GET /sql   q → sql-concat   app.js:21 → sql-concat:15
  [open] GET /search q → html-output
  [open] POST /admin/items → missing-authz
引擎 → 派生 param(intent 17, tier 2, needs_approval)
点了批准 → execute 200
  [candidate] GET /sql q → sql-concat
              note: 黑盒探测命中:1 条候选发现,请求 R0011-39e1,R0012-5a36
```

同一个文件里的**参数化查询**(`/safe`)没有产出线索 —— sanitizer 识别生效。

## 验收

```
whitebox  6 个测试:路由表(含 auth 标记)/ sql 拼接产线索而参数化不产 /
          missing-authz 只标未保护的路由 / 不保留源码正文与密钥 / 跳过 vendor / 拒绝文件路径
engine    4 个测试:线索派生成 tier-2 探测且必须停 / 未命中保持未确认 /
          结算只在有证据时升候选 / rce 这类不派生
runtime   registry 覆盖测试纳入 whitebox(不注册会被抓)
```

## 与 DEVPLAN-v0.13 的差异 / 未做

- **只做 3 个栈**(JS/Py/Go),PHP/Java 只留了 source 正则与语言枚举,没有路由解析。
- **数据流是"带品味的 grep"**:同文件、同名变量、行序启发式。跨函数/跨文件 taint 没有做,
  所以既有误报(同名变量复用)也有漏报(经 helper 转手)。这是刻意的:产出恒为 code-only。
- **`missing-authz` 还没接 role_matrix 自动验证**(DEVPLAN 模块三要求)。现在它只是线索,
  用人调用 role_matrix 或多次点击验证;`probeForHypothesis` 只映射了 sql-concat 与 redirect。
- **报告没加"假设"专节**(模块四)。假设目前通过 `GET …/hypotheses` 与图里的事实可见,
  verified 发现也还没把 `file:line` 与 `request_id` 拼在同一条证据里。
- **SPA 没有源码入口**(模块四)。能力可以从对话/意图调,但没有"选目录看路由表"的界面。
- 环境变动:`55432` 上的旧集群在一次强杀后无法恢复(WAL 截断),已重建 `.pgsql/data2`
  跑在 **55433**;`acceptance-v02.ps1` 改为读 `YOUKAI_PGPORT`(默认仍是 55432)。
