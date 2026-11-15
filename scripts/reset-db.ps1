# reset-db.ps1 — 把损坏/卡死的内置 PostgreSQL 换成一个全新干净的库。
#
# 什么时候用:youkaid 起不来、日志里出现 "could not start server" /
# "shared memory block is still in use" / "interrupted while in recovery" /
# checkpointer 崩溃 这类,说明内置实例坏了。
#
# 它做什么(不删任何东西):
#   1. 停掉本会话(Console)残留的 postgres 进程(不碰 Session 0 的系统服务);
#   2. 把旧 data 目录改名成 data.corrupt-<时间戳> 留档(不删,想捞还在);
#   3. initdb 建一个全新库,超级用户 youkai / 密码 youkai_dev_pw;
#   4. 建 youkai 数据库并启动。youkaid 下次启动会自动把表结构 migrate 出来。
#
# 里面只有一个测试账本(扫描历史),代码与文档都在 git,不受影响。

$ErrorActionPreference = 'Stop'
try {
    $root  = Split-Path -Parent $PSScriptRoot
    $pgDir = if ($env:YOUKAI_PG) { $env:YOUKAI_PG } else { 'D:\tools\pg\pgsql' }
    $pgBin = Join-Path $pgDir 'bin'
    $port  = if ($env:YOUKAI_PGPORT) { [int]$env:YOUKAI_PGPORT } else { 55432 }
    $data  = Join-Path $root '.pgsql\data'
    $log   = Join-Path $root '.pgsql\server.log'
    $pw    = if ($env:YOUKAI_PG_PASSWORD) { $env:YOUKAI_PG_PASSWORD } else { 'youkai_dev_pw' }

    foreach ($exe in @('initdb.exe','pg_ctl.exe','createdb.exe','psql.exe')) {
        if (-not (Test-Path (Join-Path $pgBin $exe))) { throw "找不到 $exe(检查 YOUKAI_PG 指向的 PostgreSQL 目录:$pgDir)" }
    }

    # 1) 停掉本会话残留的 postgres(只杀 Console/SessionId=1,绝不碰系统服务 Session 0)。
    Write-Host "停止残留的内置 postgres 进程(仅当前会话)..." -ForegroundColor Cyan
    try { & "$pgBin\pg_ctl.exe" -D $data -m immediate stop 2>$null | Out-Null } catch {}
    Get-CimInstance Win32_Process -Filter "Name='postgres.exe'" |
        Where-Object { $_.SessionId -eq 1 } |
        ForEach-Object { Write-Host "  kill PID $($_.ProcessId)"; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 3   # 等 Windows 回收共享内存块

    # 2) 旧 data 改名留档(不删)。
    if (Test-Path $data) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $corpse = Join-Path $root ".pgsql\data.corrupt-$stamp"
        Write-Host "把旧 data 目录改名备份 -> $corpse(不删除)" -ForegroundColor Cyan
        Rename-Item -Path $data -NewName (Split-Path $corpse -Leaf)
    }

    # 3) initdb 全新库:超级用户 youkai,scram 密码认证。
    Write-Host "初始化全新数据库(超级用户 youkai)..." -ForegroundColor Cyan
    $pwFile = Join-Path $env:TEMP "youkai-initpw-$([guid]::NewGuid().ToString('N')).txt"
    Set-Content -Path $pwFile -Value $pw -NoNewline -Encoding ascii
    try {
        & "$pgBin\initdb.exe" -D $data -U youkai -E UTF8 --auth-host=scram-sha-256 --auth-local=trust --pwfile=$pwFile | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "initdb 失败(退出码 $LASTEXITCODE)" }
    } finally {
        Remove-Item $pwFile -ErrorAction SilentlyContinue
    }

    # 4) 启动 + 建 youkai 库。
    Write-Host "启动新实例(端口 $port)..." -ForegroundColor Cyan
    & "$pgBin\pg_ctl.exe" -D $data -l $log -o "-p $port -c listen_addresses=127.0.0.1" -w start
    if ($LASTEXITCODE -ne 0) { Write-Host "server.log 末尾:" -ForegroundColor Red; Get-Content $log -Tail 15; throw "新实例启动失败" }

    $env:PGPASSWORD = $pw
    $exists = & "$pgBin\psql.exe" -w -h 127.0.0.1 -p $port -U youkai -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='youkai'" 2>$null
    if ("$exists".Trim() -ne '1') {
        & "$pgBin\psql.exe" -w -h 127.0.0.1 -p $port -U youkai -d postgres -c "CREATE DATABASE youkai;" | Out-Null
    }

    Write-Host ""
    Write-Host "完成。全新干净的数据库已就绪(youkai@127.0.0.1:$port/youkai)。" -ForegroundColor Green
    Write-Host "现在可以双击 start-youkai.cmd 启动 youkai;表结构会在首次启动时自动建好。" -ForegroundColor Green
    Write-Host "旧的损坏数据留在 .pgsql\data.corrupt-* 里(确认不需要后可自行删除)。" -ForegroundColor DarkGray
}
catch {
    Write-Host ""
    Write-Host "重置失败:$_" -ForegroundColor Red
}
finally {
    Write-Host ""
    Read-Host "按回车关闭此窗口"
}
