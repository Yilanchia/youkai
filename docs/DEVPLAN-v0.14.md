# DEVPLAN-v0.14:web 漏洞广度 — 给每类 sink 配一个"只判存在"的黑盒探针

> 交付对象:实现者(DeepSeek)。配 DEVPLAN-v0.9(API schema)、v0.13(白盒 sink 假设)、ADR-006(点头批准)读。
> 目标:把 web 侧的存在性探针从现在的 sqli/ssti 两类,扩到覆盖白盒已能识别的 sink —— SSRF、路径穿越、开放重定向(已有)、
> 命令注入、XXE、文件上传、反序列化(识别不主动探)。每类**只判存在、不取数据、不利用**,和白盒假设一一配对验证。

## 0. 为什么做这个(缺口很具体)

v0.13 白盒能识别 7 类 sink(sql/rce/path/ssti/redirect/ssrf/deserialize)并产出假设;但 web 侧黑盒探针只有 sqli/ssti + redirect_check。
**白盒说"这参数可能通到 SSRF",黑盒却没有 SSRF 探针去验证它** —— 假设只能停在 unconfirmed。广度补齐后,
每类白盒假设都有对应黑盒探针去坐实,形成"代码线索 → 运行验证"的完整闭环;独立黑盒测试也更全。

## 0.5 不可动摇(本轮红线,逐条适用)

- **只判存在,不利用、不取数据**:SSRF 只打自己的 canary(OAST/本地回调)看是否触达,**不读内网响应正文**;路径穿越只验"能否读到一个已知无害标记文件"(如 `/etc/hostname` 的存在性信号),**不 dump 文件内容**;命令注入只用**时延/回显无害 token**判存在,**不执行真实命令产出**;XXE 只验解析器是否展开外部实体到 canary,**不外带文件**;文件上传只验"能否上传一个无害标记文件并被接受",**不传 webshell、不执行**;反序列化**只识别不主动探**(没有安全的存在性探针,交人)。
- **全部经 `discipline.Guard`**:每个探测请求过 scope + 逐请求审计;canary/OAST 回调只打 youkai 自己的端点。
- **档位**:这些主动探针都是**档 2**(写向/主动),自治循环不自动跑,停在人前点头(ADR-006);scope 需 `allow_active_probes`。
- **candidate≠verified**:探针命中产 candidate,人确认才 verified;命中也只带"存在性证据 + request_id",不带被利用的数据。
- **canary 基础设施安全**:OAST/回调端点是 youkai 本地的、带随机 token、只记"是否被触达"与来源,不接收任意数据内容。

## 1. 探针框架扩展 `internal/web/param.go` + 新增各探针文件(P0)

**目标**:把 `param` 的 class 机制扩展到新类;每类一个独立探针文件,命中语义统一(只判存在)。

**新增 class 与探针(每个对应一个白盒 sink)**:
- `ssrf`(`internal/web/ssrf.go`):把参数替换成 youkai canary URL,发一次(经 Guard),看 canary 端点**是否被目标服务器触达**。触达=SSRF candidate。不读目标取回的任何正文。
- `path`(`internal/web/pathtraversal.go`):对看起来是文件名/路径的参数,试**无害标记路径**的存在性信号(状态码/长度差分判"路径穿越可达"),**不取文件内容**。
- `cmdi`(`internal/web/cmdi.go`):命令注入**只用时延探针**(注入导致可测延迟)或无害 echo token 判存在,**绝不执行产出型命令**;需额外谨慎,默认更严的确认。
- `xxe`(`internal/web/xxe.go`):对接受 XML 的入口,提交引用 youkai canary 外部实体的无害 XML,看 canary 是否被解析器请求(=外部实体展开)。不外带本地文件。
- `upload`(`internal/web/upload.go`):对上传入口,上传一个**无害标记文件**(纯文本、随机 token、非脚本),只验"是否被接受/可再取回标记",**不传可执行内容、不尝试执行**。
- `redirect`:已有 `redirect_check`,并入统一 class 命名,保持行为。
- `deserialize`:**不加主动探针**。白盒识别到就产 `hypothesis(sink=deserialize)` 并**直接交人**(note 说明"无安全存在性探针,需人工在授权下验证"),不自动探。

**实现要点**:
- 复用现有 `param` 的请求计数/预算/guard 封装;每个探针函数签名统一,命中写 `Finding(kind=<class>)` + 存在性 `Fact`,带 request_id。
- 每类探针**最多发 N 个请求**(小上限),避免广度变成洪水;所有变体都走 Guard。

**验收**:靶场对每类各命中一条(canary 触达/延迟/标记可达);正常参数零误报;每类都带 request_id;deserialize 只产假设不发探针;全部需 `allow_active_probes`+点头。

## 2. canary / OAST 基础设施 `internal/web/canary.go`(P0,SSRF/XXE 的前提)

**目标**:youkai 内置一个本地 canary 接收端点,给 SSRF/XXE 探针用:带随机 token 的 URL,记录"是否被触达 + 来源 IP + 时间",不接收任意内容。

**实现要点**:
- canary 监听本地(或 engagement 指定的可达回调地址),每个探针生成唯一 token URL;被请求即记一条"触达"事件,关联回对应 hypothesis/intent。
- **只记触达事实,不存请求体内容**(防止变成数据外带通道);来源信息脱敏到 IP 级。
- 若目标无法回连 youkai 的 canary(网络隔离),探针如实记"无法判定(canary 未触达可能是不可达而非不存在)",不误报为"不存在"。

**验收**:SSRF 探针触发 → canary 记到触达 → 关联 hypothesis 升 candidate;canary 不存请求体;不可达时如实标"无法判定"。

## 3. 接白盒假设 + 引擎派生(P1)

**目标**:让 v0.13 的白盒 sink 假设各自派生到对应的新探针(档 2,停人前)。

- `probeForHypothesis`(v0.13 已有雏形)补全映射:ssrf→ssrf 探针、path→path 探针、rce→cmdi 探针、ssti→已有、sql→已有、redirect→redirect_check、deserialize→不派(交人)。
- 命中 → `ConfirmProbe` 升 candidate(代码+运行双证据);没命中 → unconfirmed;canary 不可达 → 标"无法判定"。
- 这些是档 2:引擎 park 成 needs_approval,审批台/对话里点头后才真发探针(ADR-006)。

**验收**:白盒 ssrf 假设 → 派 ssrf 探针(档 2 停人前)→ 点头 → canary 触达 → 升 candidate 带双证据;rce 假设派 cmdi 探针同理;deserialize 假设不派、留给人。

## 4. 报告 / SARIF / 对话(P2)

- 新类纳入报告四样证据与 SARIF(ruleId=class,candidate=warning);每条写清"存在性证据,未取数据"。
- 对话里 AI 可建议"这个上传点值得测文件上传"——仍是建议,探针档 2 点头、验证人确认。
- bench ground truth 加入新类的靶场样例(lab-target.py 增 SSRF/path/upload/cmdi 端点)。

**验收**:报告/SARIF 含新类且分级正确(多 candidate);bench 对新类算 recall/precision、越界=0、canary 不外带数据。

## 落地顺序

1. 模块二(canary 基础设施)—— SSRF/XXE 的前提,先立。
2. 模块一(各探针,只判存在)—— 核心;deserialize 只识别不探。
3. 模块三(接白盒假设 + 引擎派生,档 2 停人前)。
4. 模块四(报告/SARIF/bench)。

**每步验收锚点**:每类只判存在、不取数据/不利用/不执行;全过 Guard + 档 2 点头 + allow_active_probes;canary 只记触达不存内容、不可达时不误报;candidate≠verified;deserialize 不自动探;越界=0;`go test ./...` 全绿;安全门禁仍过。

## 一句话

给 youkai 多认识几类漏洞,但认识的方式不变:只敲门看有没有应声,不破门、不进屋、不拿东西 ——
存在性证到就停,利用留给人,拿数据这件事永远不做。
