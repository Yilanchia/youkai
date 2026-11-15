# IMPL-STATUS v0.21 — 像 harness 一样,看得见每一步

> 日期:2026-11-15 · 承接 DEVPLAN-v0.21 · `go test ./...` 全绿 · 浏览器里点出来的
> **纯体验改造**:没有新增任何能力,也没有改动任何一道闸。

## 一句话

以前点开始之后界面是哑的,要等 run 憋完;现在它每扫一下、每发现一点、每要冒险一步,
都当场出现在对话里的一行行步骤中 —— 档 2 那一行**就地能批**。

真机记录(浏览器里点的):

```
＋ 从账本推出 3 个新步骤
▸ 扫描   http://127.0.0.1:18080              tier1 得到 7 条事实、6 条候选  R0003-f462
▸ 读 API 文档 …/openapi.json                  tier1 得到 6 条事实、1 条候选  R0001-9908
▸ 探测   …/.git/config                        tier1 得到 2 条事实            R0002-fd8d
⏸ 参数探测 …/sql?q=…                          tier2 等你批准      [批准][拒绝]
■ 停下等你:有 1 个动作等你批准:param
▸ 参数探测 …/sql?q=…                          tier2 (人工批准后执行)得到 1 条事实、1 条候选  R0011-1a08
```

## 模块一 · 引擎每步回调

`internal/engine/step.go`:

- `Config.OnStep func(StepEvent)`,**nil 时零行为**(有测试钉住:`stepSeq` 必须还是 0);
- `StepEvent` 是一份**投影**,不是内部 `StepRecord`:只含
  `run_id / seq / phase / capability / tier / target / status / summary / facts / findings / request_id / reason / stop`;
- 四类相位:`derive`(推出新步骤)、`exec`(执行完一步)、`reflect`(复盘)、`stop`(为什么停);
- `status` 只有 `ok / miss / failed / parked / info` 五种 —— **miss 就是 miss**,
  不允许写"可能还需要再试"(有测试禁词)。

### 脱敏是这一层唯一的难点

`target` 走 `sanitiseTargetURL`:去掉 userinfo 和 fragment,**把所有查询参数的值换成 `…`,只留参数名**。
`https://u:pw@h/a?x=1&y=2#f` → `https://h/a?x&y=…`。
`reason` 走 `cleanReason`:只留第一行,并把 `?` 之后截断(防止后端把载荷回显进错误消息)。
`summary` 上限 240 字符。

## 模块二 · 接到 SSE

`handleEvents` 原本只是每秒推一次整图快照。现在它在同一个连接上追加 `event: step` 帧:

- **跑的时候 300ms 一拍,闲着 1s 一拍** —— 近实时,又不制造空轮询;
- 客户端带 `?since=<seq>`,断线重连/刷新都从上次看到的序号继续,**不会丢中间那段**;
- 另开 `GET /api/engagements/{id}/run-steps?since=`,供刷新时重建整段。

> 与 DEVPLAN 的一处偏离:`OnStep` 没有走 `hub.publish`,而是**先落库、再随 SSE 快照流下发**。
> 原因:pub/sub 是易失的 —— 订阅者慢一点就被丢弃,而那正是"看不到中间步骤"的老问题。
> 落库后按 seq 补发,天然幂等、可重放,也和"账本即证据"一致。

**序号由数据库分配**(`pg_advisory_xact_lock` + `MAX(seq)+1`),不是引擎自己数:
run 和人工批准的步骤可能同时追加,必须落成一个可读的顺序,而不是抢主键。

## 模块三 · 前端步骤流

`web/stream.js`(新)+ `web/chat.js` + `web/style.css`:

- 一行一步:图标(▸ 完成 / ▸ 未命中 / ✗ 失败 / ⏸ 停人前 / ↳ 复盘 / ■ 结束 / ＋ 派生)+ 能力中文名 + 目标 + 档位徽章 + 摘要 + 流水号;
- 顶部一行活动态:`正在跑(第 N 步)… / 停在 N 个动作前,等你点头 / 这一轮结束:…`;
- **档 2 那行内联 `[批准] [拒绝]`**,点批准 = 走既有 approve → execute → 检测依赖方并续跑;
- 增量渲染:只替换 `#run-stream-slot`,**不重绘整个对话**(否则会把操作员正在输入的字冲掉);
- 切换作业时清空缓存并重载该作业的流。

## 模块四 · 复盘也播出去

v0.19 的复盘结论现在多一条 `phase:"reflect"` 事件,以浅色斜体显示在步骤之间:

```
↳ 线索 #3 未被证实 —— 代码看着可疑但运行没复现,如实记为未证实
```

措辞沿用 v0.19 的诚实版本,没有另写一套"鼓励继续"的话。

## 验收

```
engine  TestStepsAreNarratedInOrder     derive→exec→stop 串起来、seq 单调、stop 带原因
        TestStepEventCarriesNoBody      查询值被抹掉、参数名保留、无正文/凭据
        TestStepEventMarksAMiss         未命中就是 miss,且不含"可能/建议"
        TestNoHookMeansNoChange         OnStep=nil 时行为零变化
        TestSanitiseTargetURL           表格测试:userinfo/fragment/值全部去掉
真机    步骤流实时出现(300ms 一采样:1 → 5 行)、刷新后历史还在、
        档 2 就地批准后新步骤接上、作业总数不变
```

## 没做的(如实)

- **没有 SSE 的 resume 头(`Last-Event-ID`)**:用的是 `?since=` 查询参数,效果等价但不算标准写法。
- **步骤流与对话消息是两块面板**:没有把步骤行混排进对话气泡里(它们语义不同,混排反而更难读)。
- **bench 不涉及**(DEVPLAN 明确说这版不碰)。
- 头部活动态的频率跟随 SSE 节拍(空闲时 1s),不是逐事件重绘。

## 一句话

能力一点没加,但它第一次像个真的 agent:**你看得见它在干什么,它就值得你信一次**。
