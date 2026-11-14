# DEVPLAN-v0.12:今晚整改 — 拆签名墙、对话历史、自主跑通

> 交付对象:实现者(DeepSeek)。配 ADR-006(本轮决策)读。**今晚必做**,三件事对应三个实测痛点。
> 原则:拆掉签名仪式这道**必需**门槛,换成 UI 点头;保留批准行/一次性消费/candidate≠verified/档 3 墙/Guard 等全部真安全属性。

## 1. 拆掉签名墙:档 2 默认走"UI 点头"(P0,最卡)

**目标**:档 2 执行不再**必需** high-auth 签名;一次清楚的 UI 批准即可。签名降级为可选。

**涉及**:`internal/api/intents.go`(`executeIntent` / `approveIntent`)、`internal/api/server.go`(配置项)。

**改法**:
- `executeIntent`:**移除**"网络目标档 2 必须有 high-auth 记录"的 428 硬墙(`intents.go:243-251` 那段)。
  改为:执行的前置条件只剩**已有未消费、指纹匹配的操作员批准行**(Condition 1,保留)+ scope 开关(Condition 3,保留)。
- 新增服务端可选开关 `require_high_auth`(默认 **false**;env `YOUKAI_REQUIRE_HIGH_AUTH=1` 或设置里开启):
  - 默认 false → 档 2 走 UI 点头,**不碰签名**。
  - true → 恢复 ADR-005 的签名校验(给需要加密把关的人)。
- `approveIntent`:`high_auth_path` 变成**可选**;不传就是普通 UI 批准,记批准行(operator + basis 自动填"UI 确认 @时间")。
  传了且 `require_high_auth`/有 key 时才验签。
- **不动**:`ApproveIntent`/`ConsumeApproval`/批准行一次性/数据库 `intents_approval_guard_trg` 触发器 —— 批准仍要一条真实批准行,AI 产生不了。

**红线保持**:批准来自**操作员 UI 点击**(令牌鉴权);chat/planner 代码路径**不得**调 approve 或 execute(保持现状,加测试钉死)。

**验收**:默认构建下,档 2 intent:UI 点"批准"→ 能执行一次 → 再执行被拒(批准已消费);全程**无需** FAIRY_AUTH_KEY;
开 `require_high_auth` 后恢复要签名;`go test ./...` 全绿;新增测试:未经操作员批准行直接 execute 仍被拒。

## 2. 对话历史:持久化 + 渲染(P0)

**目标**:对话消息存下来、刷新/切回仍在,一眼看到完整往来。

**涉及**:`internal/api/chat.go`、`internal/ledger`(存 chat 消息)、`web/chat.js`。

**改法**:
- 账本加 `chat_messages` 表(engagement_id / role(user|assistant) / content / cards(JSONB) / created_at),append-only 即可。
- `POST /api/chat` 存一条 user + 一条 assistant;`GET /api/engagements/{id}/chat` 按时间返回全历史。
- `chat.js` 进面板时先拉历史渲染,发送后追加;区分 user/assistant 气泡,卡片(scope_draft/plan/note)按原样渲染。
- 不存任何目标响应正文/凭据(延续:对话上下文只喂归一 fact/trace 摘要)。

**验收**:发几轮消息→刷新页面→历史还在且顺序正确;切到别的面板再回来历史在;历史里无凭据/响应正文。

## 3. 自主跑通:只读自己跑完,风险处停下点头(P1,拆墙后自然顺)

**目标**:确认"自主只读 → 碰档 2/敏感停 → UI 点头 → 继续"这条链在拆墙后真的顺。

**涉及**:主要是验证 + 把"停下点头"在对话/审批台里显著呈现(多为前端 + 已有引擎)。

**改法**:
- 引擎行为不变(tier-1 自治、tier-2 park 成 needs_approval、sensitive_stop)。拆墙后 park 的档 2 在审批台点"批准"即执行,不再要签名。
- 对话面板里,当引擎停在档 2 或敏感发现时,**在对话流里也插一张"需要你点头"的卡片**(带:要做什么动作、对哪个目标、为什么停、批准/拒绝),
  点批准 = 调已有 approve+execute,点拒绝 = 标 blocked。让"止损→审批→继续"在对话里看得见。
- 顶部状态把"正在自主跑 / 停在第 N 步等你点头 / 已完成"讲清楚。

**验收**:给一个会触发档 2 的靶场(如 /search 反射→param),自治只读跑完→停在 param 待批→对话/审批台出现点头卡→点批准→param 执行→继续→报告;
全程无需签名;敏感命中(PEM)时同样停下并在对话里说明。

## 4. 文档

- README「对话式用法」更新:默认点头批准、不需要签名;需要加密把关再开 `require_high_auth`。
- `youkai-sign` / high-auth 相关说明移到"高级(可选)"段,不出现在上手流里。
- ADR-006 进 INDEX。

## 落地顺序

1. 模块一(拆签名墙 → UI 点头)—— 今晚第一优先,解除最大阻塞。
2. 模块二(对话历史持久化+渲染)。
3. 模块三(自主链路 + 对话里显示点头卡)。
4. 模块四(文档)。

**每步验收锚点**:默认无需 FAIRY_AUTH_KEY 即可批准执行档 2;批准仍一次性、AI 不能自批;对话历史持久且无凭据泄漏;
自主只读跑通、风险处停下点头后继续;candidate≠verified、档 3 墙、Guard、审计全部不变;`go test ./...` 全绿;
安全门禁 `invariants.yml` 仍过(若 high-auth 相关断言需调整,只调成"require_high_auth 开启时仍验签",不删批准行/触发器检查)。

## 一句话

今晚把那道逼你签名的墙拆了,换成一句"批不批?"的点头 —— agent 能自己把只读跑完、遇险即停等你一点,
人类把关一分没少,折腾没了。
