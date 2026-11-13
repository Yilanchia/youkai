# GAPS-v0.2:给 DeepSeek 的补齐清单(账号层 + CDP 浏览器)

> 基于 Claude 对 v0.2(commit 7d6345c)的审查。编译 / `go vet` 干净,安全脊柱与不变量落地扎实。
> 本清单列两块**真·能力缺口** + 审阅者已顺手修掉的两项(记录在案)。配 DEVPLAN-v0.2 读。

## 已修(审阅者,无需 DeepSeek 再动)

- **`go test ./...` 并行 migrate 死锁(SQLSTATE 40P01)**:多包并行共用一个 PG 库时 `migrate` 抢系统目录锁。
  已给 `ledger.Migrate` 加会话级 advisory lock 串行化迁移,现默认并行稳定全绿。
- **文档漂移**:`IMPL-STATUS-v0.1` 标 superseded;`IMPL-STATUS-v0.2` 加修订 note。

## 缺口 1:账号层(P1,BOLA/IDOR/BFLA 的燃料)

**现状**:`accounts_seed` / `accounts_register` / `object_seed` / `reachability` 注册了档位但返回"本构建不实现"。
比对原语(`compare` / `role_matrix`)在,但没有喂它们的多身份 + 归属真值。

**目标**:原生吸收 Fairy 的账号层,让越权类发现有真实身份与归属。蓝本:Fairy `src/accounts.js`、
`src/highauth.js`、`src/reachability.js`、`src/session.js`。

**涉及**:新增 `internal/accounts/`;复用 `discipline`(scope/guard/highauth)、`ledger`。

**接口 / 数据**:
- 清单 `.youkai/accounts.json`:`{name, role, login:{method,url,password_env}, owns:[{type,marker}]}`;
  **密码只走 `password_env`,不入库、不回显**。
- `Provision(ctx, env)`:每账号**只登录一次** → 存命名会话(加密或 0600),账号/归属入账;登录是写方法 = 档 2。
- `Show()`:只回 name/role/owns.marker/session_ready + BOLA 配对,**不回 cookie/密码**。
- `BolaPairs()`:owner→viewer 生成 `compare`(档 1 读),不猜归属。
- `reachability`:接 `discipline.HighAuth` 验签后只读出多账号可达性图(只读、不横向)。
- `accounts_seed` / `object_seed`:需 scope `allow_object_seeding` + 档 2 人批 + confirm;每账号一个最小对象,不删不改不批量。
- `accounts_register`:需 `allow_account_provisioning` + 档 2 人批;CAPTCHA/手机/SMS/OTP → `needs_human` 不绕过;
  邮箱验证只接受人工 `verification_url`。

**实现要点**:provision/seed/register 都是**档 2**,自治循环不派,只在审批台一步一批;会话明文不入图/报告/日志;归属 marker 是自造真值,不猜。

**验收**:两账号 provision 后 `compare`/`role_matrix` 能出 `marker-in-both`/`role-restricted`;`Show` 不含凭据;
seed/register 缺 scope 开关或缺批准即拒;CAPTCHA 页不提交。

## 缺口 2:CDP 浏览器,且必须走 Guard(P1,SPA/DOM 的前提)

**现状**:`browser` 恒 `ErrUnavailable`。DeepSeek 的理由**正确**:直接用 Chrome 发页内请求会绕过
`discipline.Guard`,破坏"唯一发包通道"。所以不能简单起个无头 Chrome 了事。

**目标**:接 CDP 做渲染 / DOM / XHR 发现 / 截图,但**每个页内网络请求都经 `discipline.Guard` 校验 scope + 审计**,
越界 fetch 当场拦断。蓝本:Fairy `src/browser.js`(重点看它怎么把 CDP 网络层接到 scope 闸)。

**涉及**:`internal/web/browser.go`(现为降级桩)+ 最小 CDP 客户端(标准库 WebSocket)。

**实现要点(安全关键)**:
- `Fetch.enable` 拦截**所有**请求:每个 `Fetch.requestPaused` → 交 `discipline.Guard` 判 scope →
  in-scope 放行 + 补审计(request_id),out-of-scope `Fetch.failRequest`。**页面不得有不经 Guard 的出口。**
- CDP 控制通道只连本机 Chrome;目标流量仍逐请求过 Guard,不新开第二条 egress。
- 渲染后采 DOM 快照 / XHR 列表 / 控制台错误 / 截图;登录态注入走已存会话。
- 无本地 Chrome → 仍明确 `ErrUnavailable` + doctor 标红,不伪造。

**验收**:SPA 页拿到标题 / 动态链接 / XHR;**构造一个页内越界 fetch → 被 `Fetch.failRequest` 拦断并记审计**;
`TestNoEgressOutsideTheGuard` 仍通过(CDP 不得引入绕过 Guard 的 http 出口);无 Chrome 时降级不崩。

## 不做(边界不变)

- 档 3 自动利用内核:仍不在仓库、build tag 墙外。
- 账号层 seed/register、浏览器写操作:都是档 2,永不进自治循环,只在审批台一步一批。
