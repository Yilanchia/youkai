# Scripts

## `lab-target.py`

本地只读靶场,给端到端验收用。起在 `127.0.0.1:<port>`:

- `/.git/config` 返回 200 + `[core]` 段 → 触发 `git 配置可读` fact
- `/search?q=...` 把参数原样回显 → 让 Fairy 的 `web_scan` 产出 reflection 候选,
  进而触发 youkai 的档 2 停点(`web_param`)

```powershell
python scripts\lab-target.py 18080
```

## `mcp-call.cjs`

直连一只手的 MCP stdio,调用一个工具。用来扮演"人"的那一侧
(立 scope 护照、建 high-auth),以及手工复核手的行为。

```powershell
node scripts\mcp-call.cjs <cwd> "<script> <args>" <tool> [jsonArgs|@file]
```

参数带中文时**一定用 `@文件`**,别在命令行里内联 JSON:PowerShell 会重新分词把引号吃掉,
这是本机最容易踩的坑。

```powershell
[System.IO.File]::WriteAllText("$env:TEMP\scope.json", $json, [System.Text.UTF8Encoding]::new($false))
node scripts\mcp-call.cjs D:\fairy_fairy "src/cli.js mcp" fairy_scope_init "@$env:TEMP\scope.json"
```

## `acceptance.ps1`

整套验收:建靶场 → 立 scope → 跑循环(断言在档 2 停下)→ 步进会话(断言三种拒绝)→
渲染 HTML → 断言隔离墙。

```powershell
.\scripts\acceptance.ps1
```

需要:Go 在 `PATH`(或设置 `YOUKAI_GO`)、Python、Node、两只手在本机。
退出码非 0 表示某条断言失败。
