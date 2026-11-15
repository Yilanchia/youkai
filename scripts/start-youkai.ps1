# start-youkai.ps1 — 一键启动 youkai 控制台。
#
# 为什么需要它:youkaid.exe 是一个控制台服务端,不是 GUI。双击 exe 不会弹窗,
# 而且它需要 PostgreSQL + YOUKAI_DSN,否则一启动就退出(看着像"打不开")。
# 这个脚本把 PG 拉起、库建好、环境配好、youkaid 跑起来,并自动用浏览器打开控制台。
# 出错会停在窗口里让你看见原因,而不是一闪就关。
#
# 用法:右键“用 PowerShell 运行”,或双击仓库根目录的 start-youkai.cmd。

$ErrorActionPreference = 'Stop'
try {
    $root = Split-Path -Parent $PSScriptRoot          # 仓库根目录
    # 集群位置自动识别:这台机器上旧的 .pgsql\data 在 2026-11-15 被强杀后 WAL 截断,
    # 已重建到 .pgsql\data2(55433)。两处都可以用 YOUKAI_PGPORT / YOUKAI_PGDATA 覆盖。
    $pgDataDefault = if (Test-Path (Join-Path $root '.pgsql\data2\PG_VERSION')) {
        Join-Path $root '.pgsql\data2'
    } else {
        Join-Path $root '.pgsql\data'
    }
    $port = if ($env:YOUKAI_PGPORT) { [int]$env:YOUKAI_PGPORT } elseif ($pgDataDefault -like '*data2') { 55433 } else { 55432 }
    $db   = 'youkai'
    $pgPw = if ($env:YOUKAI_PG_PASSWORD) { $env:YOUKAI_PG_PASSWORD } else { 'youkai_dev_pw' }
    $dsn  = "postgres://youkai:$pgPw@127.0.0.1:$port/$db`?sslmode=disable"

    # PostgreSQL 二进制目录(可用 YOUKAI_PG 覆盖)。
    $pgDir = if ($env:YOUKAI_PG) { $env:YOUKAI_PG } else { 'D:\tools\pg\pgsql' }
    $pgBin = Join-Path $pgDir 'bin'
    $pgData = if ($env:YOUKAI_PGDATA) { $env:YOUKAI_PGDATA } else { $pgDataDefault }
    # server.log 可能被杀毒/安全软件短暂锁住导致 pg_ctl "Permission denied";
    # 逐个退回可写的日志名,别让日志锁挡住启动。
    $pgLog = $null
    foreach ($cand in @('server.log','server2.log',"server-$(Get-Date -Format 'yyyyMMdd-HHmmss').log")) {
        $p = Join-Path $root ".pgsql\$cand"
        try { [IO.File]::OpenWrite($p).Close(); $pgLog = $p; break } catch { continue }
    }
    if (-not $pgLog) { $pgLog = Join-Path $env:TEMP "youkai-pg.log" }

    $youkaid = Join-Path $root 'youkaid.exe'
    if (-not (Test-Path $youkaid)) {
        Write-Host "youkaid.exe 不存在,尝试用 Go 构建..." -ForegroundColor Yellow
        & go build -o $youkaid ./cmd/youkaid
        if ($LASTEXITCODE -ne 0) { throw "构建失败:请先装 Go>=1.22,或手动 go build -o youkaid.exe ./cmd/youkaid" }
    }

    # 1) PostgreSQL:没起就起。
    $env:PGPASSWORD = $pgPw
    & "$pgBin\pg_isready.exe" -h 127.0.0.1 -p $port 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        # A hard kill leaves postmaster.pid behind and pg_ctl then refuses to start.
        Remove-Item (Join-Path $pgData 'postmaster.pid') -Force -ErrorAction SilentlyContinue
        Write-Host "启动 PostgreSQL (端口 $port)..." -ForegroundColor Cyan
        & "$pgBin\pg_ctl.exe" -D $pgData -l $pgLog -o "-p $port -c listen_addresses=127.0.0.1" -w start
        $ok = $false
        foreach ($i in 1..15) {
            Start-Sleep -Seconds 1
            & "$pgBin\pg_isready.exe" -h 127.0.0.1 -p $port 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { $ok = $true; break }
        }
        if (-not $ok) {
            Write-Host "PostgreSQL 起不来。server.log 末尾:" -ForegroundColor Red
            if (Test-Path $pgLog) { Get-Content $pgLog -Tail 20 }
            throw "PostgreSQL 未能在 15 秒内就绪"
        }
    }
    Write-Host "PostgreSQL 就绪。" -ForegroundColor Green

    # 2) 确保 youkai 库存在(表结构由 youkaid 自己 Migrate)。
    $have = & "$pgBin\psql.exe" -w -h 127.0.0.1 -p $port -U youkai -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$db'" 2>$null
    if ("$have".Trim() -ne '1') {
        Write-Host "创建数据库 $db ..." -ForegroundColor Cyan
        & "$pgBin\psql.exe" -w -h 127.0.0.1 -p $port -U youkai -d postgres -c "CREATE DATABASE $db;" | Out-Null
    }

    # 3) 环境:DSN、会话密钥(持久化,保证重启后已存会话仍可解密)。
    $env:YOUKAI_DSN = $dsn
    if (-not $env:YOUKAI_SESSION_KEY -and -not $env:FAIRY_SESSION_KEY) {
        $keyFile = Join-Path $root '.youkai\session.key'
        if (-not (Test-Path $keyFile)) {
            New-Item -ItemType Directory -Force -Path (Split-Path $keyFile) | Out-Null
            -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) }) | Set-Content -NoNewline $keyFile
        }
        $env:YOUKAI_SESSION_KEY = (Get-Content -Raw $keyFile).Trim()
    }
    if (-not $env:FAIRY_AUTH_KEY) {
        Write-Host "提示:未设 FAIRY_AUTH_KEY —— 档 2(利用/写方法)执行被禁用,只读与审批记录仍可用。" -ForegroundColor Yellow
    }

    # 4) 端口用 8799,避开你以前在 :8787 跑的旧应用残留的 service worker。
    #    youkaid 在前台跑(日志留在本窗口);后台轮询等它就绪再开浏览器,避免首开连接被拒。
    $addr = '127.0.0.1:8799'
    $uiPort = 8799
    # 先停掉占着 8799 的旧 youkaid(上次没退干净会让新实例 bind 失败)。只停 youkaid,不碰别的。
    $busy = Get-NetTCPConnection -LocalPort $uiPort -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $busy) {
        $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -eq 'youkaid') {
            Write-Host "停掉占用 $uiPort 的旧 youkaid (PID $($p.Id))..." -ForegroundColor Cyan
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 800
        } elseif ($p) {
            throw "端口 $uiPort 被进程 $($p.ProcessName) (PID $($p.Id)) 占用,且它不是 youkaid;请先处理它,或设别的端口。"
        }
    }
    $tok  = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
    $url  = "http://$addr/#token=$tok"
    Write-Host "控制台:$url" -ForegroundColor Green
    Start-Job -ArgumentList $url, $addr -ScriptBlock {
        param($u, $a)
        foreach ($i in 1..60) {
            Start-Sleep -Milliseconds 300
            try { Invoke-WebRequest -UseBasicParsing -Uri "http://$a/" -TimeoutSec 2 | Out-Null; Start-Process $u; break } catch {}
        }
    } | Out-Null
    & $youkaid -addr $addr -token $tok
}
catch {
    Write-Host ""
    Write-Host "启动失败:$_" -ForegroundColor Red
}
finally {
    Write-Host ""
    Read-Host "按回车关闭此窗口"
}
