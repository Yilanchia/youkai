# IMPL-STATUS v0.14 — web 漏洞广度:每类 sink 一个"只判存在"的探针

> 日期:2026-11-15 · 承接 DEVPLAN-v0.14 · `go test ./...` 全绿
> 新增:`internal/web/canary.go`(本地回调)、`sinks.go`(ssrf / path / cmdi / xxe / upload 探针)、
> `probe_helpers.go`;`param` 的 class 扩到 7 类;引擎把白盒假设映射到对应探针。
> **deserialize 明确拒绝探测**(见下)。

## 一句话

给 youkai 多认识几类漏洞,认识的方式没变:**只敲门看有没有应声,不破门、不进屋、不拿东西。**

## 一 · canary:youkai 自己的回调端点

SSRF 和 XXE 只能靠"目标反向请求我们"来判定,所以 youkai 起了一个**只记触达**的监听器:

- 绑定 `127.0.0.1:0`(随机端口),URL 形如 `http://127.0.0.1:<port>/c/<128bit token>`;
- 命中时只记 `{token, 时间, 来源 IP(脱敏到 host)}`;
- **不读请求体**:处理器连 `r.Body` 都没碰,固定回 `ok` —— 这个端点不是数据入口;
- 每次探测一个新 token,猜不出来;
- 目标回连不了(网络隔离)时,探针写"未能判定",**不当成不存在**;
- 需要公网回调的部署用 `YOUKAI_CANARY_BASE` 指向自己的隧道,转发到那个端口。

## 二 · 五类新探针(全部档 2,全部过 Guard)

| class | 判据 | 明确不做 |
|---|---|---|
| `ssrf` | canary 被目标请求(命中数>0) | 不读目标取回的任何内容 |
| `xxe` | 提交的 XML 外部实体指向 canary,canary 被请求 | 不带本地文件、不回带内容 |
| `path` | 越界路径返回了标记文件内容(与基线比对) | 不保存文件内容,只判"标记出现了" |
| `cmdi` | 注入 `sleep` 后响应比基线慢 ≥1.2s | **只送 sleep**,不执行产出型命令、不读输出 |
| `upload` | 纯文本标记文件被接受(2xx,或 201) | 不传可执行内容、不尝试运行/取回执行 |
| `deserialize` | —— | **不探测**。请求该 class 会直接报错:"反序列化没有安全的存在性探针,请人工验证" |

每个探针最多 2–3 个变体,共享 param 的 6 请求硬上限;命中产 `Finding(kind=<class>)` + 一条存在性 Fact,
**都带 request_id**(没有 request_id 的会被观察构建器丢掉)。

## 三 · 引擎:每条白盒线索都有对应探针

`probeForHypothesis` 现在映射:

| 白盒 sink | 派生 | 档 |
|---|---|---|
| `sql-concat` | param · sqli | 2 |
| `ssti` | param · ssti | 2 |
| `ssrf` | param · ssrf | 2 |
| `path` | param · path(+marker) | 2 |
| `rce` | param · cmdi | 2 |
| `xxe` | param · xxe | 2 |
| `redirect` | redirect_check | 1 |
| `deserialize` / `html-output` | **不派生** | —— 交人 |

全部档 2:引擎 park 成 `needs_approval`,点头才发。

## 实测(本机靶场,五类各命中一条)

```
engagement 4 · 5 次批准执行 · 16 次请求 · 5 条 candidate
  [high]   参数可触发服务端请求(SSRF)         evidence: canary_hits=1, canary_remote=127.0.0.1
  [high]   XML 外部实体被解析(XXE)
  [high]   参数可穿越目录读到 web 根之外的文件   baseline_len=9 → hit_len=18(只有长度,无内容)
  [high]   参数可能进入命令执行(时延证据)       baseline_ms=187 → hit_ms=2114, payload_shape=sleep
  [medium] 上传入口接受任意文本文件
```

三条红线的落地证据:

1. **canary 不存内容** —— 测试 `TestCanaryKeepsNoBody` 往 canary 发 `SECRET-PAYLOAD-123`,
   校验记录里只有 token/时间/IP;
2. **命令注入不产生真实输出** —— `TestCMDIProbeMeasuresDelayOnly` 断言 finding 里不含 `uid=`/`root:`,
   并且只带 `payload_shape=sleep`;
3. **反序列化不许主动探** —— `TestDeserializeIsRefusedNotProbed` 要求 `param{classes:[deserialize]}` 报错。

## 验收

```
web    7 个新测试:canary 命中 / 未命中说"未能判定" / 穿越按标记判定 / cmdi 只测时延 /
       反序列化被拒 / upload 只送文本 / canary 不存 body
engine 3 个白盒测试仍绿(映射改成按 sink 查表)
report 新 kind 的 counter 模板补齐(ssrf/xxe/path-traversal/cmdi/upload)
```

## 与 DEVPLAN-v0.14 的差异 / 未做

- **报告/SARIF 没加"假设"专节**,也没把新类加进 bench 的 ground truth(lab 端点已加,recall 未跑)。
- **XXE 只在 POST 文本入口试**,不试 multipart/JSON 内嵌 XML;`upload` 只判 2xx/201,不判断类型校验是否真存在。
- **`html-output` 不映射探针**:反射类线索没有本轮的探针,留给人。
- **`path` 的判定依赖 `marker` 参数**:没有标记文件时只能给到"无命中",不会声称安全。
- **环境**:旧集群(55432)已废弃,当前用 `.pgsql/data2`(55433);`youkaid` 与 PG 这次是**放在
  长驻后台任务里**跑的 —— 之前的 `Start-Process` 起的进程会随工具调用结束被回收。
