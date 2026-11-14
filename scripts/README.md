# Scripts

## `lab-target.py`

本地只读靶场,给端到端验收用。起在 `127.0.0.1:<port>`:

- `/.git/config` 返回 200 + `[core]` 段 → 触发 `git 配置可读` fact
- `/search?q=...` 把参数原样回显 → 让 `scan` 产出 reflection 候选,
  进而触发引擎的档 2 停点(`param`)

```powershell
python scripts\lab-target.py 18080
```

## `acceptance-v02.ps1`

整套 v0.2 验收:起本机 PG 实例 → 建全新数据库 → 构建并启动 `youkaid` → 建带护照的作业 →
跑一轮只读链(断言停在档 2)→ 断言审计/事实/候选状态 → 走完"批准 → high-auth → 单次执行 →
批准不可复用" → 断言数据库层三道触发器 → 渲染报告。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acceptance-v02.ps1
```

依赖:Go 在 PATH(或 `YOUKAI_GO`)、Python、curl.exe、本机 PostgreSQL 17 二进制
(`.pgsql/data` 或 `D:\tools\pg\pgsql`)。退出码非 0 表示某条断言失败。

断言清单覆盖:无令牌 401、跨 Origin 403、通配符护照被拒、自治段只跑 tier 1、
门口四样证据、审计逐请求、批准/ high-auth 双条件、批准一次性、三道数据库触发器、报告可复现,
以及 v0.3 的两块新能力:

- **账号层**:清单加载 → provision(档 2 双条件)→ 会话就绪且视图无凭据 → seed(三道开关 + 批准)
  → BOLA 配对 → 引擎派 `compare` → 越权对象产出 `bola` 候选。
- **CDP 浏览器**:真实 Chrome 渲染 SPA 页(标题 + 同源 XHR),页内 `fetch` 去 out-of-scope 主机
  被 `Fetch.failRequest` 拦断并记审计;无 Chrome 时断言降级路径。

- **运行时配置**:保存 LLM 配置 → 读回不含 key 明文 → 库里的 settings 行也没有 key →
  对靶场的假 `/chat/completions` 测连通(ok + 延迟)→ 对坏端点测出 error →
  配置变更落 `config:llm` 审计。
- **护照编辑**:全字段建作业 → 字段都落库 → 通配符被拒 → 放宽护照落 `config:scope` 审计。

- **证据报告**:四样齐备(缺则标 incomplete)、两次渲染字节一致、快照带 sha256 且拒 UPDATE、
  SARIF 2.1.0(四样进 properties)、披露包无 verified 时 409、改护照后再出快照哈希不同。

本地靶场 `lab-target.py` 为此增加了 `/login`、`/orders/1`(正确受限)、
`/orders/2`(故意 IDOR)、`/spa`(含越界 beacon)、`/api/data`、`/signup`(CAPTCHA)、
`/chat/completions`(假的 OpenAI 兼容端点,给「测试连接」用)。