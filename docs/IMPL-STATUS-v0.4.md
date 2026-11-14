# IMPL-STATUS v0.4 — 运行时配置(LLM API + scope 护照 + 配置 API)

> 日期:2026-11-14 · 承接 DEVPLAN-v0.4 · `go test ./...` 全绿 · `scripts/acceptance-v02.ps1` 全通过
> 新增:`internal/secretbox/`、`internal/config/`、`internal/planner/manager.go`、
> `internal/api/{llm,scope}.go`、SPA 可编辑配置面板与护照编辑器。

## 一句话

"配置 · 隔离墙"从只能看变成**能安全地改**:模型怎么连、护照到哪、预算多少都在 UI 里设,
保存即热生效、secret 加密落库、每次改动留痕 —— **但墙和放行权不在配置面里**。

## 落地对照

| DEVPLAN-v0.4 | 状态 | 交付 |
|---|---|---|
| 一 · 配置持久层 + 加密 | ✅ | `settings` 表、`internal/config`、`internal/secretbox` |
| 二 · LLM API 配置 + test + 热替换 | ✅ | `planner.Manager`、`/api/config/llm`、`/api/config/llm/test` |
| 三 · scope 完整编辑 + 审计 | ✅ | `PUT /api/engagements/{id}/scope`、`POST` 全字段透传 |
| 四 · SPA 可编辑面板 | ✅ | 配置面板(LLM 表单 + 护照编辑器)、墙保持只读 |
| 五 · 文档 + 验收 | ✅ | README 配置参考、验收脚本 +21 条断言 |

## 一 · 配置持久层

```sql
CREATE TABLE settings (
  key TEXT PRIMARY KEY, value JSONB, secret_enc BYTEA,
  updated_at TIMESTAMPTZ, updated_by TEXT );
```

- **secret 只能是密文**:`internal/secretbox` 是平台唯一的加密构造
  (scrypt N=2^14/r=8/p=1 → AES-256-GCM,nonce/salt 随密文,associated data 绑定 key,
  所以一条 secret 不能被嫁接到另一个设置项上)。
- **无密钥就拒绝**:`config.ErrSecretWithoutKey` → HTTP 428 + 明确提示
  (`YOUKAI_SESSION_KEY` 或改用 `key_from_env`)。**不退化成明文/base64** —— 比会话存储更严,
  因为 LLM key 通常是付费凭据。
- **读路径永不返回 secret**:`Get` 只回 `value` + `hasSecret bool`;
  `GetSecret` 只给"构造客户端"用,不出现在任何 HTTP 响应里。
- **三态 secret**:`nil` 保持、`""` 清除、其他值替换 —— 所以"不改 key"和"删掉 key"可区分。

验收(`internal/config/store_test.go`,5 项,真 PG):
`TestPutGetNeverReturnsTheSecret`(响应/库行/JSON 全无明文,`GetSecret` 能解)、
`TestSecretRefusedWithoutPassphrase`(拒绝保存,且没建行)、`TestSecretThreeStates`、
`TestWrongPassphraseCannotDecrypt`、`TestInvalidValueRejected`。

## 二 · LLM 配置 + 热替换

**来源优先级**:UI 保存的配置 > 环境变量(`planner.FromEnv`)> 禁用。

- `planner.Manager` 持有一个可原子替换的 `*Planner`;引擎/服务端拿的是 Manager 这个**稳定引用**,
  所以保存配置不影响正在跑的调用。`api.proposer()` 在每次新建 run 时问一次
  `Manager.Enabled()`,关掉 LLM 时引擎拿到 nil —— 确定性循环照跑。
- 可配字段全部放开:`temperature` / `timeout_s` / `max_tokens`(默认 0 / 120 / 1200)。
- `POST /api/config/llm/test` 发一次 `max_tokens=16` 的最小 completion,**不写
  `planner_calls`**(它是连通性检查,不是一次规划),只回 `{ok, latency_ms, error}`。
- **保存前先解析 key**:启用但 key 取不到(比如引用的环境变量为空)会被 400 拒绝且**不落库** ——
  否则库里的配置和进程里的状态会打架。

验收(`internal/api/llm_test.go`,8 项):往返保存/读回、key 不回显、直填 key 加密落库、
无会话密钥拒绝(428)、base_url/model/温度/二选一校验、test 的成功/失败路径、
关闭后 `proposer()==nil`、配置变更进审计。

## 三 · 护照完整编辑

- `POST /api/engagements` 现在透传全部字段并 `NewScope` 归一 —— UI 只填一部分时,
  安全默认(只读方法集、限速、预算、响应体上限)自动补齐。
- `PUT /api/engagements/{id}/scope`:校验 → 无变化直接返回 → 更新 →
  **写一条 `audit_log`**(`method=CONFIG`, `url=config:scope`,detail =
  改前/改后的 include/exclude/methods/开关/预算/过期/basis/operator)。
- 校验规则不变:空 include、`*`、`*.tld`、basis < 8、已过期 → 400 并回显原因。
- 响应带 `widened` 摘要让 UI 提示"这次放宽了";它不是执行判据 ——
  真正的闸仍是 guard 的逐请求检查 + 档 2 的人批。

验收(`internal/api/llm_test.go` 的 scope 段):通配符被拒、全字段建作业落库、
编辑生效并回读、`widened=true`、审计行含 `allow_object_seeding` 与操作员。

## 四 · SPA

- **LLM 段**改为表单:启用开关、base_url、model、temperature/timeout/max_tokens、
  key 来源二选一(环境变量名 / 直填 password 框)、保存、测试连接、状态回显。
  key 框永不预填,只显示 `key_present` 与 `key_source`。
- **护照段**:当前护照只读展示 + 「编辑护照…」「+ 新建作业…」;
  编辑器含 include/exclude、methods 勾选、五个档 2/私网开关、预算、rps、过期、
  依据、操作员,并在写方法与档 2 开关旁提示"解锁的是档 2 能力,仍要人批"。
- **墙段保持只读**:利用提供者、构建、high-auth 状态、能力分档表 —— **没有任何开关**。

真实渲染已验证(截图见交付):配置面板预填当前值、`编辑护照…` 模态预填当前 scope。

## 五 · 验收(真机)

`scripts/acceptance-v02.ps1` 新增 21 条断言,最后输出:

```
== runtime config ==
ok  LLM config saved (PUT /api/config/llm)
ok  LLM config is live from settings
ok  the env-referenced key is reported present
ok  the LLM key is not echoed in the save response
ok  LLM config reads back / the LLM key is not echoed on read
ok  LLM test reports a working endpoint        (对靶场假 /chat/completions)
ok  LLM test reports latency
ok  the LLM test does not return model output
ok  LLM test reports a failing endpoint as an error
ok  the settings row does not hold the key in the clear
ok  the LLM change is audited / the LLM audit row carries no key
ok  engagement created from a full passport form
ok  every passport field was persisted
ok  a top-level wildcard passport is refused (edit path)
ok  passport edit applied / the API reports the change as widening
ok  scope widening is audited / the scope audit names the operator
ALL ACCEPTANCE ASSERTIONS PASSED
```

## 顺带修掉的一个真问题

**迁移死锁**:`internal/config` 加入后,四个包并行跑 `go test` 时同时 `Migrate`,
`CREATE INDEX` 的 ShareLock 与并行测试的行锁互相等待,PostgreSQL 判 40P01。
原来只有 advisory lock(串行),但输家会直接失败。现在 `Migrate` 对
`40P01`/`40001`/`55P03` **退避重试**(最多 5 次),并行测试恢复稳定。

## 与 DEVPLAN-v0.4 的差异 / 未做

- **LLM 配置是全局单条**(`settings.key='llm'`),不按作业隔离。DEVPLAN 没有要求按作业;
  单机单操作员场景下"一个模型配置"更符合直觉。
- **`accounts_show` 之类的账号配置仍在清单文件**(`.youkai/accounts.json`),
  没搬进 settings 表。DEVPLAN-v0.4 只覆盖 LLM 与 scope;账号清单里有 `password_env`,
  搬进数据库反而会让"密码来源"变得模糊。
- **审计面板只显示当前作业的审计**,而 `config:llm` 记在 `engagement='*'` 名下,
  所以 LLM 配置变更要在配置面板看 `updated_by/at`,审计面板里看不到 —— 已知取舍,
  要合并显示需要给审计查询加一个"平台级"选项。
- **`settings` 表没有 UPDATED BY 的身份认证**:`updated_by` 是请求体里自報的字符串
  (v1 单操作员无登录)。多用户/RBAC 仍按 ADR-003 不做。
- **没有配置回滚**:history 只在 `audit_log` 的 detail 里,没有"恢复到上一版"的端点。
