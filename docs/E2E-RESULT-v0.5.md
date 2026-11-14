# E2E 结果回填 — v0.5 主线闭环

> 执行者:DeepSeek(本机 PowerShell + 浏览器) · 剧本:[docs/E2E-VALIDATION-v0.5.md](E2E-VALIDATION-v0.5.md)
> 日期:2026-11-14

```
环境:Go 1.22(toolchain 1.27.4)/ PostgreSQL 16(D:\tools\pg,端口 55432)/ Chrome(CDP)
靶场:scripts/lab-target.py 18080(本机环回)
服务:youkaid 127.0.0.1:8794,FAIRY_AUTH_KEY + YOUKAI_SESSION_KEY 已配置

A 自动化:[x] ALL PASSED   (0 FAIL,末行 ALL ACCEPTANCE ASSERTIONS PASSED)

B 人工走查:
  B1 建作业/护照校验 ...... [x] 通配符 `*` 被拒且原因可见;合法护照(不填过期)建成
  B2 无 scope 拒绝 ......... [x] 400「这个作业还没有护照(include 为空)」
  B3 自治只读停在档 2 ...... [x] 4 步 / 15 次允许 / 0 阻断 / 8 条候选,停在 needs_approval(param)
  B4 审批台一次一个/无全放 . [x] 1 张卡,四样齐,按钮只有「批准这一步」「执行这一步(一次性)」
  B5 无 high-auth 拒绝 ..... [x] 428「high_auth_path is required for a network target」
  B6 批准一步即消费 ........ [x] 执行 1 次(5 个 request_id),再执行 403「no unconsumed approval」
  B7 账号 provision 无凭据 . [x] alice/bob 均 ready,界面无 cookie/密码,有清单权限告警
  B8 BOLA candidate ....... [x] 引擎派 2 条 compare(档 1),/orders/2 产出 bola 候选
  B9 verified 需判定 ....... [x] 不勾选 →「必须先勾选确认。」;勾选+note → verified
  B10 快照四样齐 ........... [x] 快照 #3 / sha 9da5c5cc… / HTML 落盘;每条 finding 四段展开
  B11 SARIF 分级 ........... [x] 2.1.0,8 results:verified→error(1),candidate→warning(7)
  B12 披露只含 verified .... [x] 无 verified → 409;有 → 只含 1 条,CVSS 标「估计」,无候选
  B13 墙段无开关 ........... [x] 隔离墙卡片 0 个 input/button
  B14 LLM 配置 key 不回显 .. [x] 保存后热生效;测连通「正常 · 2ms」;key 框始终为空
```

## 走查中发现并修掉的问题(6 个,均为真机暴露)

| # | 现象 | 根因 | 修复 |
|---|---|---|---|
| 1 | 建作业时 `expires_at: ""` 直接 500 级解析错误 | `Scope.ExpiresAt` 是 `time.Time`,空字符串解不动 | `Scope.UnmarshalJSON` 把 `""` 读作"不设过期";SPA 空值直接不发送该字段 |
| 2 | 任何错误提示都被流式刷新秒清 | `renderApprovals()` 每次都 `banner(...)`,而 `render()` 每个 SSE tick 都跑 | 待批提示改为视图内的元素,banner 只由用户动作写 |
| 3 | 无护照也能启动 run(空转) | `startRun` 不校验护照 | 无 include/非法护照 → 400 并说明 |
| 4 | 全部请求被拦的 run 只报 LLM 噪声 | stop_reason 取最后一步的消息 | 新增 `blockedRunReason`:全被拦时如实说"所有请求都被护照拦断" |
| 5 | 批准后无法执行(按钮被重置为 disabled) | 执行按钮状态来自点击时的局部变量,SSE 重渲染后复原 | 状态从账本 `intent.approved` 派生 |
| 6 | 档 2 执行在 scope 开关缺失时**先消费批准再失败**,意图永久卡在 `active` | 开关检查在能力内部、消费之后 | 新增"条件 3:护照开关"前置检查(未满足返 428 且不消费);派发失败把意图退回 `needs_approval` |

## 结论

**主线闭环成立。** 关键不变式逐条验证:

- 无 scope 不动作(B2);自治段只跑档 1,遇档 2 停在人前(B3/B4);
- 档 2 需要"人批 + high-auth"两条件,缺一即拒(B5),执行一次即消费(B6);
- candidate 必须人工判定才升 verified(B9);报告四样齐、快照带 sha 且不可改(B10);
- SARIF 分级正确(B11);披露包只收 verified、无授权依据不出(B12);
- 配置面碰不到墙(B13),key 永不回显(B14);
- 全程 0 越界请求、0 凭据/正文泄漏。

## 遗留(不阻断,已记录)

- **切换作业后立刻切面板可能短暂显示空态**:SSE 重连窗口内 `state.intents` 尚未刷新;显式刷新或等一个 tick 即正常。属显示层时序,不影响数据与执行。
- **披露包的 CVSS 仍是按严重度带宽的估计值**(无向量分解),文本已明确标注。
- **审计面板只显示当前作业的审计**;`config:*` 记在 `engagement='*'` 下(已知取舍)。
