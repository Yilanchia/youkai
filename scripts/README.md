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

断言清单(共 36 条)覆盖:无令牌 401、跨 Origin 403、通配符护照被拒、自治段只跑 tier 1、
门口四样证据、审计逐请求、批准/ high-auth 双条件、批准一次性、三道数据库触发器、报告可复现。