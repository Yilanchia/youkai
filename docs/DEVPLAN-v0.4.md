# DEVPLAN-v0.4:运行时配置全面化(LLM API 配置 + scope 护照编辑 + 配置 API)

> 交付对象:实现者(DeepSeek)。配 ADR-002/003/004、DEVPLAN-v0.2、IMPL-STATUS-v0.3 读。
> 目标:把现在**只读**的"配置 · 隔离墙"面板补成**可编辑**的配置面 —— LLM(大模型)API 可在 UI 配置并安全保存、
> scope 护照所有旋钮可在 UI 填、配置改动进审计。不碰安全不变量:key 不回显、改配置不等于放行、档位墙不动。

## 0. 现状诊断(为什么说"配置还没有")

1. **LLM API 只能靠环境变量**:`planner.FromEnv` 读 `YOUKAI_LLM_BASE_URL/API_KEY/MODEL`,启动时一次性生效;
   `Temperature=0`、`Timeout=120s`、`MaxTokens=1200` **写死**。UI 的 `/api/config` 只回 `LLMInfo`(enabled/model/
   base_url/key_present),**纯展示,改不了**。想换模型/调温度/填 key 都得改环境变量重启。
2. **scope 护照 UI 够不着大部分旋钮**:新建作业表单只收 `include`+`basis`,`methods` 写死 `GET/HEAD/OPTIONS`。
   `exclude`/`allow_active_probes`/`allow_waf_probe`/`max_requests`/`rate`/`expires_at`/`approver` 全部无法从 UI 设 ——
   而这些正是档 2 能力(param/waf)能否开、作业何时过期的开关。
3. **没有配置持久层**:LLM 配置无处存(PG 没有 settings 表);key 也没有"加密落盘或引用环境变量"的安全保存路径。

## 0.5 不可动摇(继承,逐条适用于本次)

- **key 绝不回显**:任何 API 响应、日志、报告、探索图都不得出现 LLM API key 明文;UI 只显示 `key_present: true/false`
  与来源(env 名或"已加密保存")。
- **改配置 ≠ 放行**:配置面只改"怎么连模型 / scope 边界",**不触碰**档位墙、不改 approve、不改 candidate→verified。
- **scope 仍是硬前提**:护照非法(空 include、`*`、`*.tld`、basis 太短、已过期)一律拒绝保存,错误回显给操作员。
- **只听 127.0.0.1 + 令牌 + Origin 校验**:所有新增配置端点走现有鉴权中间件,写操作需令牌。
- LLM 是**补位**:没配/配错时,确定性循环照跑,不得因配置缺失而崩。

## 1. 配置持久层 `internal/config`(P0,先建)

**目标**:一张 PG settings 表存运行时配置;secret 只存加密密文或环境变量引用,绝不明文。

**涉及**:`internal/ledger/schema.sql`(加表)、`internal/config/store.go`、`internal/config/crypto.go`、`internal/config/*_test.go`。

**schema(加进 schema.sql,保持 `IF NOT EXISTS` 幂等)**:
```sql
CREATE TABLE IF NOT EXISTS settings (
  key         TEXT PRIMARY KEY,          -- 如 'llm'
  value       JSONB NOT NULL,            -- 非秘密字段明文存(base_url/model/temperature/...)
  secret_enc  BYTEA,                     -- AES-256-GCM 密文(如 API key);可空
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by  TEXT                       -- 操作员标识(来自令牌会话)
);
```

**secret 加密**:复用 `internal/accounts/session.go` 的 AES-256-GCM + scrypt 蓝本(**抽成 `internal/config/crypto.go` 共享,或直接调用**),passphrase 取 `YOUKAI_SESSION_KEY`(兼容 `FAIRY_SESSION_KEY`)。无 key 时:**拒绝保存 secret**(返回明确错误,提示设置会话密钥或改用环境变量引用),不退化成明文落盘 —— 这是比会话存储更严的选择,因为 LLM key 常是付费凭据。

**接口**:
```go
type Store struct{ /* pg pool + crypto */ }
func (s *Store) Get(ctx, key string) (value json.RawMessage, hasSecret bool, err error)  // 永不返回解密后的 secret
func (s *Store) GetSecret(ctx, key string) (string, error)                                // 仅服务端内部用(构造 planner 时)
func (s *Store) Put(ctx, key string, value json.RawMessage, secret *string, by string) error
```

**验收**:Put 带 secret → 库里 `secret_enc` 是密文、`value` 里无 secret;Get 不含 secret;无会话密钥时 Put secret 报错;`updated_by`/`updated_at` 落库。

## 2. LLM API 配置 `internal/planner` + 配置 API(P0)

**目标**:LLM 的 provider/base_url/model/key/temperature/timeout/max_tokens 可在 UI 配、保存、**热生效**(不重启),可测连通。

**配置来源优先级**(写进文档):**UI 保存的配置 > 环境变量(`planner.FromEnv`)> 禁用**。key 两种来源二选一:
- `key_from_env`: 填环境变量名,key 不落库(最安全,推荐);或
- `key`: 直接填,服务端加密存 `settings.secret_enc`(需会话密钥)。

**planner 可配字段**(放开现在写死的):`Temperature`、`Timeout`、`MaxTokens` 全部来自配置,给安全默认(0 / 120s / 1200)。

**API**(挂现有鉴权):
- `GET /api/config/llm` → `{enabled, base_url, model, temperature, timeout_s, max_tokens, key_present, key_from_env}`(**无 key 明文**)。
- `PUT /api/config/llm` → 存配置;校验 base_url 是 http(s)、model 非空;保存后**重建 planner 实例并热替换**到引擎/派发器。
- `POST /api/config/llm/test` → 用当前(或请求体里待测)配置发一次最小 completion,只回 `{ok, latency_ms, error}`,**不回模型输出正文、不写账本**。

**热替换**:planner 实例在 server 里要可原子替换(`sync.Mutex`/`atomic.Pointer`),`PUT` 成功后新作业/新调用用新配置;正在跑的调用不受影响。

**安全**:test 端点同样经 scope 无关的本地鉴权;测试调用打的是模型端点(非目标),不经 `discipline.Guard`(它本就豁免,见 egress_test 对 planner 的例外);key 若来自 env,test 时现取现用,不落库。

**验收**:UI 填 base_url+model+key_from_env → 保存 → `GET` 显示 enabled 且 key_present;test 通 → `{ok:true,latency_ms}`;填错 base_url → 保存被拒;key 直填 → 库里密文、响应无明文;保存后不重启即可被新一轮 planner 使用;无会话密钥且直填 key → 明确报错。

## 3. scope 护照完整编辑器(P0)

**目标**:新建 / 编辑作业时,护照的**每个旋钮**都能在 UI 填;非法护照保存前被拒并回显原因。

**UI 暴露的护照字段**(对齐 `discipline.Scope`):
- `include[]`(授权目标,必填)、`exclude[]`(排除优先)。
- `methods[]`(默认只读 `GET/HEAD/OPTIONS`;勾选才加写方法,UI 要提示"写方法会放开登录/播种等档 2 能力")。
- `allow_active_probes`(开 param/param_adaptive 档 2)、`allow_waf_probe`(开 waf 档 2):开关,默认关,旁注"仅存在性探测,不绕过/不取数据"。
- `max_requests`(请求预算)、`rate`(限速)、`expires_at`(过期时间,必填或给默认如 +7d)。
- `basis`(授权依据 ≥8 字,必填)、`approver`(授权人)。

**API**:
- 建作业 `POST /api/engagements`:body 收完整 scope JSON(现在只拼 include+methods,改成透传 UI 的全字段);服务端 `NewScope` 归一 + 校验,非法返回 400 带原因(已有校验,扩到全字段)。
- 编辑 `PUT /api/engagements/{id}/scope`:更新护照;**变更写一条 audit_log**(谁、何时、改了什么边界),因为放宽 scope 是安全相关动作。
- `GET /api/engagements/{id}` 回当前 scope 供 UI 预填。

**安全**:护照校验规则不变(空 include / `*` / `*.tld` / 短 basis / 已过期一律拒);**放宽 scope(加 include、开 active/waf、加写方法)必须记审计**;收紧不强制但也记。编辑不影响已跑出的审计与发现。

**验收**:UI 建作业能设 exclude/active/waf/max_requests/expires/approver 并生效;`*` 被拒;开 `allow_active_probes` 后 param 能力才可能被派(仍停在档 2 等人批);改 scope 落 audit_log;过期护照拒绝保存。

## 4. SPA 配置面板改为可编辑 `web/app.js` + `web/style.css`(P1)

**目标**:"配置 · 隔离墙"从只读变可编辑;新建作业模态补全护照字段。

- **LLM 段**:provider/base_url/model 文本框、temperature/timeout/max_tokens 数字框、key 来源二选一(env 名 / 直填 password 框)、**保存**按钮、**测试连接**按钮(显示 ok/延迟/错误)。key 框永不预填、永不回显已存值,只显示 `key_present`。
- **隔离墙段**:保持只读展示(provider.available、档位表、high-auth 状态)—— 这是墙的状态,不是可配项,**不给开关**。
- **新建/编辑作业模态**:补 exclude、methods 勾选、active/waf 开关、max_requests、rate、expires、approver;写方法与 active/waf 旁边给红字提示其解锁的是档 2 能力。
- 所有写操作走令牌;保存成功后重新拉 `/api/config` 刷新。

**验收**:配置面能保存 LLM 并测连通;墙段无任何可点开关;建作业模态能设全部护照字段;保存后状态刷新;key 框不回显。

## 5. 文档与脚本

- README「配置参考」补:UI 配置优先于环境变量;LLM key 两种来源;scope 全字段含义;改 scope 会记审计。
- `scripts/acceptance-v02.ps1` 增断言:PUT llm 配置 → GET 不含 key 明文 → test 连通(可对一个假端点断言 error 路径);建作业带 active/waf/exclude → 库里 scope 正确 → 改 scope 落 audit。

## 落地顺序

1. 模块一(配置持久层 + 加密)—— 地基,secret 安全存储先立住。
2. 模块二(LLM API 配置 + test + 热替换)。
3. 模块三(scope 护照完整编辑 + 审计)。
4. 模块四(SPA 可编辑面板)。
5. 模块五(文档 + 验收脚本)。

**每步验收锚点**:LLM key 在响应/日志/库 value 里零明文;无会话密钥时直填 key 被拒;改配置不触碰档位墙/approve;放宽 scope 必记 audit;LLM 配错时确定性循环照跑;`go test ./...` 全绿(PG 测试走 `YOUKAI_TEST_DSN`)。

## 一句话

把"只能看"的配置面补成"能安全地改":模型怎么连、scope 到哪、预算多少,都在 UI 里设得明白、存得安全、改得留痕 ——
但隔离墙和放行权仍不在配置面里,它们是骨头,不是旋钮。
