# youkai end-to-end acceptance
#
# What this proves is that youkai stops where it must - not that it can break in:
#   * the autonomous section only executes tier 1
#   * a tier-2 step parks at needs_approval and runs nothing without a human
#   * an approval is explicit, bound to one proposal, and single-use
#   * the OSS build ships no exploitation provider
#
# usage: powershell -ExecutionPolicy Bypass -File .\scripts\acceptance.ps1
# exit 0 = every assertion passed.

$ErrorActionPreference = "Continue"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$port = 18080
$ws = Join-Path $root "lab\acceptance-ws"
$project = Join-Path $root "lab\acceptance"
$youkai = Join-Path $root "youkai.exe"
$utf8 = New-Object System.Text.UTF8Encoding($false)

$script:failures = 0

function Assert($ok, $message) {
    if ($ok) {
        Write-Host "ok    $message" -ForegroundColor Green
    } else {
        Write-Host "FAIL  $message" -ForegroundColor Red
        $script:failures++
    }
}

# Run youkai and return output + exit code without turning expected failures into
# terminating errors (PowerShell 5.1 turns native stderr into ErrorRecords).
function Invoke-Youkai {
    param([string[]]$Arguments)
    $out = & $youkai @Arguments 2>&1 | Out-String
    return @{ Out = $out; Code = $LASTEXITCODE }
}

function Write-Json($path, $obj) {
    $json = $obj | ConvertTo-Json -Depth 6 -Compress
    [System.IO.File]::WriteAllText($path, $json, $utf8)
}

# ---- 0. clean state + build ------------------------------------------------
Write-Host "`n== build ==" -ForegroundColor Cyan

# Start from an empty engagement: a reused step session would make "PROPOSAL 1"
# and "step 1" assertions depend on history instead of behaviour.
foreach ($stale in @($project, $ws)) {
    if (Test-Path $stale) { Remove-Item -Recurse -Force $stale }
}
if (Test-Path $youkai) { Remove-Item -Force $youkai }

$go = if ($env:YOUKAI_GO) { $env:YOUKAI_GO }
      elseif (Get-Command go -ErrorAction SilentlyContinue) { "go" }
      elseif (Test-Path "D:\tools\go\bin\go.exe") { "D:\tools\go\bin\go.exe" }
      else { $null }
if (-not $go) {
    Write-Host "FAIL  no go toolchain found (set YOUKAI_GO)" -ForegroundColor Red
    exit 1
}
& $go build -o youkai.exe ./cmd/youkai 2>&1 | Out-String | Write-Host
if (-not (Test-Path $youkai)) {
    Write-Host "FAIL  youkai does not build" -ForegroundColor Red
    exit 1
}
Write-Host "ok    youkai builds" -ForegroundColor Green

# ---- 1. lab target ---------------------------------------------------------
Write-Host "`n== lab target ==" -ForegroundColor Cyan
$python = if ($env:YOUKAI_PYTHON) { $env:YOUKAI_PYTHON }
          elseif (Test-Path "D:\pycharm\python3\python.exe") { "D:\pycharm\python3\python.exe" }
          else { "python" }

$server = Start-Process -FilePath $python -ArgumentList "scripts\lab-target.py", "$port" `
    -RedirectStandardError "$env:TEMP\youkai-acceptance-server.err" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

try {
    $probe = Invoke-WebRequest -Uri "http://127.0.0.1:$port/.git/config" -UseBasicParsing -TimeoutSec 5
    Assert ($probe.StatusCode -eq 200) "lab target answers /.git/config with 200"

    # ---- 2. hands doctor ---------------------------------------------------
    Write-Host "`n== hands ==" -ForegroundColor Cyan
    if (-not (Test-Path (Join-Path $root ".youkai\hands.json"))) {
        Invoke-Youkai @("init") | Out-Null
    }
    # The acceptance run gets its OWN workspace so its append-only graph is
    # isolated from any real engagement state.
    New-Item -ItemType Directory -Force -Path (Join-Path $ws ".youkai") | Out-Null
    Copy-Item (Join-Path $root ".youkai\hands.json") (Join-Path $ws ".youkai\hands.json") -Force
    $doctor = Invoke-Youkai @("hands")
    Assert ($doctor.Out -match "fairy:.*tools") "fairy hand connected"
    Assert ($doctor.Out -match "verdex:.*tools") "verdex hand connected"
    Assert ($doctor.Out -match "ok\s+fairy_scope_init") "fairy_scope_init advertised"
    Assert ($doctor.Out -match "ok\s+analyze_target") "verdex analyze_target advertised"
    Assert ($doctor.Out -match "available=false") "OSS build has no exploitation provider"

    # ---- 3. the human authorises the lab ----------------------------------
    Write-Host "`n== scope ==" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $project | Out-Null
    $scopeFile = Join-Path $env:TEMP "youkai-acceptance-scope.json"
    Write-Json $scopeFile @{
        project  = $project
        include  = @("127.0.0.1")
        basis    = "self-hosted lab: youkai acceptance"
        operator = "acceptance"
        limits   = @{ allow_private = $true; allow_active_probes = $true; methods = @("GET", "HEAD", "OPTIONS") }
    }
    node scripts\mcp-call.cjs D:\fairy_fairy "src/cli.js mcp" fairy_scope_init "@$scopeFile" 2>$null | Out-Null
    Assert (Test-Path (Join-Path $project "fairy.scope.json")) "scope passport created by the human side"

    # ---- 4. autonomous run: tier 1 only, stops at the door ----------------
    Write-Host "`n== run (autonomous) ==" -ForegroundColor Cyan
    $seed = "http://127.0.0.1:$port/search?q=acceptance"
    $run = Invoke-Youkai @("run", "--workspace", $ws, "--project", $project, "--seed", $seed, "--max-steps", "6", "--concurrency", "2")
    Write-Host $run.Out
    Assert ($run.Code -eq 10) "run exits 10 (stopped at needs_approval)"
    Assert ($run.Out -match "stop: needs_approval") "run reports needs_approval"
    Assert ($run.Out -match "web_param") "the tier-2 follow-up was derived"
    Assert ($run.Out -match "exact request") "the door is explained (exact request)"
    Assert ($run.Out -match "min impact") "the door is explained (min impact)"
    Assert ($run.Out -match "stop condition") "the door is explained (stop condition)"
    Assert ($run.Out -notmatch "web_param\s+tier 2 via fairy\s+ok") "the loop never executed the tier-2 action"

    $graph = Invoke-Youkai @("graph", "--workspace", $ws, "--json")
    Assert ($graph.Out -match "\.git/config") "the /.git/config hit reached the graph"
    Assert ($graph.Out -match "request_id") "facts carry request_id evidence"
    Assert ($graph.Out -match '"tier": 2') "the parked intent is recorded as tier 2"

    # ---- 5. stepping mode: explicit, bound, single-use --------------------
    Write-Host "`n== step ==" -ForegroundColor Cyan
    $propose = Invoke-Youkai @("step", "propose", "--next", "--workspace", $ws, "--project", $project)
    Write-Host $propose.Out
    Assert ($propose.Out -match "PROPOSAL 1 \(NOT executed\)") "a proposal is produced and not executed"
    $fp = ([regex]::Match($propose.Out, "sha256:[0-9a-f]{64}")).Value
    Assert ($fp.Length -gt 20) "the proposal carries a fingerprint"

    $r = Invoke-Youkai @("step", "execute", "--workspace", $ws)
    Assert ($r.Code -ne 0) "execute without approval is refused"

    $r = Invoke-Youkai @("step", "approve", "--workspace", $ws, "--fingerprint", $fp, "--operator", "acceptance", "--basis", "lab")
    Assert ($r.Code -ne 0) "approve without --confirm is refused"

    $r = Invoke-Youkai @("step", "approve", "--workspace", $ws, "--fingerprint", "sha256:deadbeef", "--operator", "acceptance", "--basis", "lab", "--confirm")
    Assert ($r.Code -ne 0) "approve with a mismatched fingerprint is refused"

    $r = Invoke-Youkai @("step", "approve", "--workspace", $ws, "--fingerprint", $fp, "--operator", "acceptance", "--basis", "self-hosted lab", "--confirm")
    Assert ($r.Code -eq 0) "approve with the exact fingerprint + confirm is accepted"

    $exec = Invoke-Youkai @("step", "execute", "--workspace", $ws)
    Write-Host $exec.Out
    Assert ($exec.Out -match "EXECUTED step 1") "the approved action executes exactly once"

    $again = Invoke-Youkai @("step", "execute", "--workspace", $ws)
    Assert ($again.Code -ne 0) "a consumed approval cannot execute a second time"

    # ---- 6. read-only report ----------------------------------------------
    Write-Host "`n== html ==" -ForegroundColor Cyan
    $page = Join-Path $project "timeline.html"
    $r = Invoke-Youkai @("html", "--workspace", $ws, "--project", $project, "--out", $page)
    Assert (Test-Path $page) "timeline rendered"
    $html = [System.IO.File]::ReadAllText($page, $utf8)
    Assert ($html -notmatch "<script") "timeline has no scripts"
    Assert ($html -notmatch 'src=') "timeline has no external resources"
    Assert ($html -match "Timeline") "timeline has its sections"
}
finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
}

if ($script:failures -ne 0) {
    Write-Host "`n$($script:failures) ACCEPTANCE ASSERTION(S) FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "`nALL ACCEPTANCE ASSERTIONS PASSED" -ForegroundColor Green
exit 0
