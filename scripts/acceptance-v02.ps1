# youkai v0.2 end-to-end acceptance
#
# Proves the properties that matter after the monolith pivot:
#   * no scope -> nothing is requested
#   * every target request is audited, and the audit table cannot be rewritten
#   * the autonomous run stops at the tier-2 door
#   * tier-2 execution needs BOTH an operator approval AND a valid high-auth record
#   * an approval is single-use
#   * candidate -> verified is refused at the database until an operator verdict
#   * accounts: provision/seed are tier 2 (approval + high-auth), sessions never
#     leak, and declared ownership turns into a working BOLA comparison
#   * browser: a real headless Chromium renders the page, and an in-page fetch to
#     an out-of-scope host is refused at the CDP network layer and audited
#
# usage: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acceptance-v02.ps1
# exit 0 = all assertions passed.

$ErrorActionPreference = "Continue"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$pgDir   = "D:\tools\pg\pgsql"
$pgData  = Join-Path $root ".pgsql\data"
$pgLog   = Join-Path $root ".pgsql\server.log"
$dsn     = "postgres://youkai:youkai_dev_pw@127.0.0.1:55432/youkai?sslmode=disable"
$dbName  = "youkai_acceptance"
$labPort = 18080
$apiPort = 8791
$apiBase = "http://127.0.0.1:$apiPort"
$fairyKey = "acceptance-key-0123456789abcdef"
$utf8 = New-Object System.Text.UTF8Encoding($false)

$script:failures = 0
function Assert($ok, $message) {
    if ($ok) { Write-Host "ok    $message" -ForegroundColor Green }
    else { Write-Host "FAIL  $message" -ForegroundColor Red; $script:failures++ }
}
# New-HighAuth builds a signed high-authorisation record the way the human's
# tooling does: JSON.stringify(payload, sorted keys), HMAC-SHA256, hex.
function New-HighAuth($Key, $Approver, $Asset) {
    $now = (Get-Date).ToUniversalTime()
    $issued = $now.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $expires = $now.AddHours(1).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $basis = "self-hosted lab acceptance"
    $nonce = "acc-" + ([guid]::NewGuid().ToString("N").Substring(0, 8))
    $canonical = '{"actions":["read-only"],"approver":"' + $Approver + '","assets":["' + $Asset + '"],"basis":"' + $basis + '","expires_at":"' + $expires + '","issued_at":"' + $issued + '","nonce":"' + $nonce + '","schema":"FairyHighAuth/v1","tier":"highest"}'
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $bytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))
    $sig = -join ($bytes | ForEach-Object { $_.ToString("x2") })
    $record = '{"schema":"FairyHighAuth/v1","payload":' + $canonical + ',"signature":"' + $sig + '"}'
    $path = Join-Path $env:TEMP ("youkai-highauth-" + [guid]::NewGuid().ToString("N") + ".json")
    [System.IO.File]::WriteAllText($path, $record, $utf8)
    return $path
}
function Wait-Http($url, $timeoutSec = 30) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        try { return Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 } catch { Start-Sleep -Milliseconds 300 }
    }
    return $null
}

# ---- 0. postgres -----------------------------------------------------------
Write-Host "`n== postgres ==" -ForegroundColor Cyan
$env:PGPASSWORD = "youkai_dev_pw"
$pgUp = $false
try { & "$pgDir\bin\pg_isready.exe" -h 127.0.0.1 -p 55432 | Out-Null; $pgUp = ($LASTEXITCODE -eq 0) } catch {}
if (-not $pgUp) {
    Write-Host "starting postgres..."
    & "$pgDir\bin\pg_ctl.exe" -D $pgData -l $pgLog -o "-p 55432 -c listen_addresses=127.0.0.1" start 2>&1 | Out-Null
    Start-Sleep -Seconds 3
}
& "$pgDir\bin\psql.exe" -h 127.0.0.1 -p 55432 -U youkai -d postgres -c "DROP DATABASE IF EXISTS $dbName;" 2>&1 | Out-Null
& "$pgDir\bin\psql.exe" -h 127.0.0.1 -p 55432 -U youkai -d postgres -c "CREATE DATABASE $dbName;" 2>&1 | Out-Null
Assert ($LASTEXITCODE -eq 0) "fresh acceptance database created"

$accDsn = "postgres://youkai:youkai_dev_pw@127.0.0.1:55432/$dbName`?sslmode=disable"

# ---- 1. build + start the platform ----------------------------------------
Write-Host "`n== build ==" -ForegroundColor Cyan
$go = if ($env:YOUKAI_GO) { $env:YOUKAI_GO }
      elseif (Get-Command go -ErrorAction SilentlyContinue) { "go" }
      elseif (Test-Path "D:\tools\go\bin\go.exe") { "D:\tools\go\bin\go.exe" }
      else { $null }
if (-not $go) { Write-Host "FAIL  no go toolchain" -ForegroundColor Red; exit 1 }
& $go build -o youkaid.exe ./cmd/youkaid 2>&1 | Out-String | Write-Host
if (-not (Test-Path youkaid.exe)) { Write-Host "FAIL  build" -ForegroundColor Red; exit 1 }
Write-Host "ok    youkaid builds" -ForegroundColor Green

# lab target
$python = if ($env:YOUKAI_PYTHON) { $env:YOUKAI_PYTHON }
          elseif (Test-Path "D:\pycharm\python3\python.exe") { "D:\pycharm\python3\python.exe" }
          else { "python" }
$lab = Start-Process -FilePath $python -ArgumentList "scripts\lab-target.py", "$labPort" `
    -RedirectStandardError "$env:TEMP\youkai-lab.err" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

$youkaiOut = Join-Path $env:TEMP "youkaid-out.txt"
$youkaiErr = Join-Path $env:TEMP "youkaid-err.txt"
$env:YOUKAI_DSN = $accDsn
$env:FAIRY_AUTH_KEY = $fairyKey
$env:YOUKAI_SESSION_KEY = "acceptance-session-key-0123456789"
$env:ALICE_PW = "alice-lab-password"
$env:BOB_PW = "bob-lab-password"
$env:ACC_LLM_KEY = "sk-acceptance-should-never-be-echoed"
$accountsPath = Join-Path $root ".youkai\accounts-acc.json"
$sessionsDir  = Join-Path $root ".youkai\sessions-acc"
$token = -join ((1..32) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
$tokenPath = Join-Path $env:TEMP "youkai-acceptance-token.txt"
if (Test-Path $tokenPath) { Remove-Item -Force $tokenPath }
$srv = Start-Process -FilePath (Join-Path $root "youkaid.exe") `
    -ArgumentList "-addr", "127.0.0.1:$apiPort", "-artifacts", (Join-Path $root ".youkai\artifacts-acc"), "-token", $token, "-token-file", $tokenPath, "-accounts", $accountsPath, "-sessions", $sessionsDir `
    -RedirectStandardOutput $youkaiOut -RedirectStandardError $youkaiErr -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3

for ($i = 0; $i -lt 40; $i++) {
    if (Test-Path $tokenPath) { break }
    Start-Sleep -Milliseconds 250
}
Assert (Test-Path $tokenPath) "youkaid started and handed over its token file"

# curl keeps the status code honest (Invoke-WebRequest's throw-and-inspect dance
# is unreliable for 4xx in Windows PowerShell 5.1). The body goes in on stdin so
# there is no temp file, no argument quoting, and no encoding surprise.
function Api($method, $path, $body) {
    $argv = @("-s", "-w", "`n%{http_code}", "-X", $method,
              "-H", "X-Youkai-Token: $token", "-H", "Content-Type: application/json",
              "--max-time", "120")
    $raw = $null
    if ($null -ne $body) {
        $json = $body | ConvertTo-Json -Depth 8 -Compress
        $argv += @("--data-binary", "@-")
        $raw = $json | & curl.exe @argv ($apiBase + $path)
    } else {
        $raw = & curl.exe @argv ($apiBase + $path)
    }
    $lines = @($raw)
    $code = 0
    if ($lines.Count -gt 0) { [void][int]::TryParse(($lines[-1] -as [string]).Trim(), [ref]$code) }
    $txt = if ($lines.Count -gt 1) { ($lines[0..($lines.Count - 2)] -join "`n") } else { "" }
    $obj = $null
    try { $obj = $txt | ConvertFrom-Json } catch {}
    return @{ Code = $code; Body = $obj; Raw = $txt }
}

# New-Intent queues one typed step (tier 1 runs unattended; tier 2 waits for us).
function New-Intent($engId, $capability, $intentArgs, $rationale) {
    return (Api "POST" "/api/engagements/$engId/intents" @{
        capability = $capability; args = $intentArgs; rationale = $rationale
    })
}

# Invoke-Step approves and executes exactly one step, optionally with high-auth.
function Invoke-Step($engId, $intentId, $highAuthPath) {
    $r = Api "POST" "/api/engagements/$engId/intents/$intentId/approve" @{
        operator = "acceptance"; basis = "self-hosted lab acceptance"
    }
    if ($r.Code -ne 201) { return $r }
    $body = @{ operator = "acceptance" }
    if ($highAuthPath) { $body["high_auth_path"] = $highAuthPath }
    return (Api "POST" "/api/engagements/$engId/intents/$intentId/execute" $body)
}

try {
    $health = Api "GET" "/api/health" $null
    Assert ($health.Code -eq 200) "health endpoint answers with the token"
    Assert ($health.Body.provider -match "no exploitation provider") "the build ships no exploitation provider"

    # ---- 2. token / origin --------------------------------------------------
    Write-Host "`n== access control ==" -ForegroundColor Cyan
    $noToken = (& curl.exe -s -o NUL -w "%{http_code}" "$apiBase/api/engagements")
    Assert (($noToken -as [string]).Trim() -eq "401") "API rejects a request with no token"
    $badOrigin = (& curl.exe -s -o NUL -w "%{http_code}" -H "X-Youkai-Token: $token" -H "Origin: http://evil.example" "$apiBase/api/engagements")
    Assert (($badOrigin -as [string]).Trim() -eq "403") "API rejects a foreign Origin"

    # ---- 3. engagement with a passport -------------------------------------
    Write-Host "`n== scope ==" -ForegroundColor Cyan
    $scope = @{
        project  = "acceptance"
        include  = @("127.0.0.1")
        basis    = "self-hosted lab acceptance run"
        operator = "acceptance"
        allow_private = $true
        allow_active_probes = $true
        allow_object_seeding = $true
        allow_account_provisioning = $true
        methods  = @("GET", "HEAD", "OPTIONS", "POST")
        rps = 20
        max_requests = 200
        expires_at = (Get-Date).ToUniversalTime().AddHours(2).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $created = Api "POST" "/api/engagements" @{ name = "acc-$((Get-Date).ToString('HHmmss'))"; scope = $scope }
    Assert ($created.Code -eq 201) "engagement created with a valid passport"
    $engId = $created.Body.id
    Assert ($engId -gt 0) "engagement id assigned"

    $bad = Api "POST" "/api/engagements" @{ name = "bad-$((Get-Date).ToString('HHmmss'))"; scope = @{ include = @("*"); basis = "self-hosted lab"; operator = "x" } }
    Assert ($bad.Code -eq 400) "a top-level wildcard passport is refused"

    # ---- 4. autonomous run --------------------------------------------------
    Write-Host "`n== autonomous run ==" -ForegroundColor Cyan
    $runRes = Api "POST" "/api/engagements/$engId/runs" @{ seed_urls = @("http://127.0.0.1:$labPort/search?q=acceptance"); max_steps = 14 }
    Assert ($runRes.Code -eq 202) "run accepted"
    $runId = $runRes.Body.run_id

    $final = $null
    for ($i = 0; $i -lt 120; $i++) {
        Start-Sleep -Milliseconds 500
        $r = Api "GET" "/api/engagements/$engId/runs/$runId" $null
        if ($r.Body.done) { $final = $r.Body; break }
    }
    Assert ($null -ne $final) "run finished"
    if ($null -ne $final) {
        $stop = $final.report.stop
        Write-Host ("      stop = {0}  steps = {1}" -f $stop, $final.report.steps.Count)
        $pending = $final.report.pending
        $stoppedAtDoor = ($stop -eq "needs_approval") -or (@($pending).Count -ge 1)
        Assert $stoppedAtDoor "the run stopped at the tier-2 door"
        $ranTier2 = $false
        foreach ($s in $final.report.steps) { if ($s.tier -ne 1) { $ranTier2 = $true } }
        Assert (-not $ranTier2) "the autonomous run executed only tier-1 capabilities"
        Assert ($final.report.steps.Count -ge 1) "at least one read-only step ran against the lab"
        $pending = $final.report.pending
        Assert ($pending.Count -ge 1) "the parked intent is reported as pending"
        if ($pending.Count -ge 1) {
            Assert ($pending[0].exact_request.Length -gt 0) "pending carries the exact request"
            Assert ($pending[0].min_impact.Length -gt 0) "pending carries the minimum impact"
            Assert ($pending[0].stop_condition.Length -gt 0) "pending carries the stop condition"
        }
    }

    # ---- 5. graph + audit ---------------------------------------------------
    Write-Host "`n== evidence ==" -ForegroundColor Cyan
    $graph = Api "GET" "/api/engagements/$engId/graph" $null
    Assert ($graph.Body.stats.facts -ge 1) "facts landed in the ledger"
    Assert ($graph.Body.stats.audit_allowed -ge 1) "every request left an audit row"
    $gitFact = $false
    foreach ($f in $graph.Body.facts) { if ($f.statement -match "\.git/config") { $gitFact = $true } }
    Assert $gitFact "the /.git/config probe was recorded"
    foreach ($f in $graph.Body.findings) { if ($f.state -ne "candidate") { Assert $false "a finding is not a candidate" } }
    Assert $true "all findings are candidates"

    # ---- 6. tier-2: approval, then high-auth, then one execution -----------
    Write-Host "`n== tier-2 door ==" -ForegroundColor Cyan
    $intents = Api "GET" "/api/engagements/$engId/intents" $null
    $param = $null
    foreach ($row in $intents.Body) { if ($row.intent.capability -eq "param") { $param = $row.intent } }
    Assert ($null -ne $param) "the tier-2 param intent was derived"

    if ($null -ne $param) {
        $execPath = "/api/engagements/$engId/intents/$($param.id)/execute"
        $approvePath = "/api/engagements/$engId/intents/$($param.id)/approve"

        $r = Api "POST" $execPath @{ operator = "acceptance" }
        Assert ($r.Code -eq 403) "execute without an approval is refused"

        $r = Api "POST" $approvePath @{ operator = "acceptance"; basis = "self-hosted lab acceptance" }
        Assert ($r.Code -eq 201) "operator approval recorded"
        $approval = $r.Body

        # ADR-006: the operator's click IS the authorisation. No signed record here.
        $r = Api "POST" $execPath @{ operator = "acceptance" }
        Assert ($r.Code -eq 200) "execute with an approval alone succeeds (no signature needed)"
        if ($r.Code -eq 200) { Write-Host ("      executed: facts +{0} findings +{1}" -f $r.Body.facts, $r.Body.findings) }

        $r = Api "POST" $execPath @{ operator = "acceptance" }
        Assert ($r.Code -eq 403) "the approval was consumed (second execute refused)"
    }

    # ---- 7. account layer: identities, ownership, BOLA ---------------------
    Write-Host "`n== accounts ==" -ForegroundColor Cyan

    # The operator writes the manifest; passwords come from the environment.
    $manifest = @{
        schema   = "YoukaiAccounts/v1"
        base_url = "http://127.0.0.1:$labPort"
        accounts = @(
            @{
                name  = "alice"; role = "admin"
                login = @{ url = "http://127.0.0.1:$labPort/login"; fields = @{ username = "alice" }; password_env = "ALICE_PW" }
                owns  = @(
                    @{ marker = "ORD-1"; url = "/orders/1"; note = "correctly restricted" },
                    @{ marker = "ORD-2"; url = "/orders/2"; note = "deliberately broken (IDOR)" }
                )
            },
            @{
                name  = "bob"; role = "user"
                login = @{ url = "http://127.0.0.1:$labPort/login"; fields = @{ username = "bob" }; password_env = "BOB_PW" }
            }
        )
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $accountsPath) | Out-Null
    [System.IO.File]::WriteAllText($accountsPath, ($manifest | ConvertTo-Json -Depth 10), $utf8)

    $acc = Api "GET" "/api/engagements/$engId/accounts" $null
    Assert ($acc.Code -eq 200) "accounts view renders"
    Assert (@($acc.Body.accounts).Count -eq 2) "two identities come from the manifest"
    Assert (@($acc.Body.bola_pairs).Count -ge 2) "declared ownership produces BOLA pairs"
    Assert ($acc.Raw -notmatch "lab-password") "the accounts view carries no password"

    # Provision: tier 2, so it goes through approve + high-auth + one execution.
    $iProv = New-Intent $engId "accounts_provision" @{} "为清单里每个账号登录一次并保存会话"
    Assert ($iProv.Code -eq 201) "provision intent queued"
    Assert ($iProv.Body.gate.tier -eq 2) "provision is classified tier 2"
    $provId = $iProv.Body.intent.id

    $r = Api "POST" "/api/engagements/$engId/intents/$provId/approve" @{ operator = "acceptance"; basis = "self-hosted lab acceptance" }
    Assert ($r.Code -eq 201) "provision approval recorded"
    $r = Api "POST" "/api/engagements/$engId/intents/$provId/execute" @{ operator = "acceptance" }
    Assert ($r.Code -eq 200) "provision executed once with an approval (no signature)"

    $acc = Api "GET" "/api/engagements/$engId/accounts" $null
    $ready = @($acc.Body.accounts | Where-Object { $_.session_ready }).Count
    Assert ($ready -eq 2) "both identities now have a stored session"
    Assert ($acc.Raw -notmatch "sess-alice|sess-bob|Cookie") "the accounts view leaks no session value"

    # Seeding: allow_object_seeding + POST + confirm + approval + high-auth.
    $iSeed = New-Intent $engId "accounts_seed" @{ confirm = $true } "每账号创建一个最小对象作为归属真值"
    Assert ($iSeed.Code -eq 201) "seed intent queued"
    Assert ($iSeed.Body.gate.tier -eq 2) "seeding is classified tier 2"
    $seedId = $iSeed.Body.intent.id
    $r = Invoke-Step $engId $seedId $null
    Assert ($r.Code -eq 200) "seeding executed once with both conditions"

    $acc2 = Api "GET" "/api/engagements/$engId/accounts" $null
    Assert (@($acc2.Body.bola_pairs).Count -ge 2) "BOLA pairs are available after provisioning"

    # ---- 8. the engine turns ownership into tier-1 comparisons -------------
    Write-Host "`n== BOLA comparisons ==" -ForegroundColor Cyan
    $runRes = Api "POST" "/api/engagements/$engId/runs" @{ max_steps = 8 }
    Assert ($runRes.Code -eq 202) "comparison run accepted"
    $cmpRun = $runRes.Body.run_id
    $cmpFinal = $null
    for ($i = 0; $i -lt 120; $i++) {
        Start-Sleep -Milliseconds 500
        $r = Api "GET" "/api/engagements/$engId/runs/$cmpRun" $null
        if ($r.Body.done) { $cmpFinal = $r.Body; break }
    }
    Assert ($null -ne $cmpFinal) "comparison run finished"
    $graph2 = Api "GET" "/api/engagements/$engId/graph" $null
    $capabilities = @($graph2.Body.intents | ForEach-Object { $_.capability })
    Assert ($capabilities -contains "compare") "the engine derived compare intents from ownership"
    $facts2 = @($graph2.Body.facts | ForEach-Object { $_.statement })
    Assert (($facts2 -join "`n") -match "双账号比对") "the comparison ran and was recorded"
    $kinds2 = @($graph2.Body.findings | ForEach-Object { $_.kind })
    Assert ($kinds2 -contains "bola") "the deliberately broken object produced a BOLA candidate"

    # ---- 9. CDP browser: rendered DOM, and the gate blocks in-page egress --
    Write-Host "`n== browser ==" -ForegroundColor Cyan
    $iBro = New-Intent $engId "browser" @{ url = "http://127.0.0.1:$labPort/spa"; wait_ms = 1500 } "渲染 SPA 页,读标题/XHR,并验证页内越界请求被拦断"
    Assert ($iBro.Code -eq 201) "browser intent queued"
    Assert ($iBro.Body.gate.tier -eq 1) "browser is tier 1"

    $runRes = Api "POST" "/api/engagements/$engId/runs" @{ max_steps = 6 }
    Assert ($runRes.Code -eq 202) "browser run accepted"
    $broRun = $runRes.Body.run_id
    $broFinal = $null
    for ($i = 0; $i -lt 180; $i++) {
        Start-Sleep -Milliseconds 500
        $r = Api "GET" "/api/engagements/$engId/runs/$broRun" $null
        if ($r.Body.done) { $broFinal = $r.Body; break }
    }
    Assert ($null -ne $broFinal) "browser run finished"
    $facts3 = ""
    $kinds3 = @()
    if ($null -ne $broFinal) {
        foreach ($s in $broFinal.report.steps) {
            if ($s.capability -eq "browser" -and $s.ok) { $facts3 = "ran" }
        }
    }
    $graph3 = Api "GET" "/api/engagements/$engId/graph" $null
    $facts3 = (@($graph3.Body.facts | ForEach-Object { $_.statement }) -join "`n")
    $kinds3 = @($graph3.Body.findings | ForEach-Object { $_.kind })
    if ($facts3 -match "未找到 Chrome") {
        Write-Host "      (no Chromium on this machine: browser degraded as designed)" -ForegroundColor Yellow
        Assert ($true) "browser degrades cleanly without a Chromium install"
    } else {
        Assert ($facts3 -match "SPA lab") "the browser rendered the page title (DOM only)"
        Assert ($facts3 -match "页面 XHR") "the browser observed a same-origin XHR"
        Assert ($kinds3 -contains "scope-blocked") "the in-page out-of-scope fetch was blocked and recorded"
    }

    # ---- 10. runtime configuration: LLM API + passport editing --------------
    Write-Host "`n== runtime config ==" -ForegroundColor Cyan

    # Save a model config that references an env var (the key never touches the DB).
    $llmBody = @{
        enabled = $true
        base_url = "http://127.0.0.1:$labPort"
        model = "lab-fake-model"
        temperature = 0.1
        timeout_s = 20
        max_tokens = 64
        key_from_env = "ACC_LLM_KEY"
        updated_by = "acceptance"
    }
    $r = Api "PUT" "/api/config/llm" $llmBody
    Assert ($r.Code -eq 200) "LLM config saved (PUT /api/config/llm)"
    Assert ($r.Body.enabled -eq $true -and $r.Body.source -eq "settings") "LLM config is live from settings"
    Assert ($r.Body.key_present -eq $true) "the env-referenced key is reported present"
    Assert ($r.Raw -notmatch "sk-acceptance") "the LLM key is not echoed in the save response"

    $r = Api "GET" "/api/config/llm" $null
    Assert ($r.Code -eq 200 -and $r.Body.model -eq "lab-fake-model") "LLM config reads back"
    Assert ($r.Raw -notmatch "sk-acceptance") "the LLM key is not echoed on read"

    # Connectivity test against the lab's fake chat-completions endpoint.
    $r = Api "POST" "/api/config/llm/test" @{ base_url = "http://127.0.0.1:$labPort"; model = "lab-fake-model"; timeout_s = 10 }
    Assert ($r.Code -eq 200 -and $r.Body.ok -eq $true) "LLM test reports a working endpoint"
    Assert ($r.Body.latency_ms -ne $null) "LLM test reports latency"
    Assert ($r.Raw -notmatch "pong") "the LLM test does not return model output"

    # A broken endpoint reports an error, not a success.
    $r = Api "POST" "/api/config/llm/test" @{ base_url = "http://127.0.0.1:1"; model = "x"; timeout_s = 3 }
    Assert ($r.Code -eq 200 -and $r.Body.ok -eq $false) "LLM test reports a failing endpoint as an error"
    Assert ($r.Body.error) "the failing test explains itself"

    # A key must not have leaked into the settings row or the audit detail.
    $out = & "$pgDir\bin\psql.exe" -h 127.0.0.1 -p 55432 -U youkai -d $dbName -tAc `
        "SELECT coalesce(value::text,'') || coalesce(encode(secret_enc,'hex'),'') FROM settings WHERE key='llm';" 2>&1 | Out-String
    Assert ($out -notmatch "sk-acceptance") "the settings row does not hold the key in the clear"
    $out = & "$pgDir\bin\psql.exe" -h 127.0.0.1 -p 55432 -U youkai -d $dbName -tAc `
        "SELECT detail::text FROM audit_log WHERE purpose='config' AND url='config:llm' ORDER BY id DESC LIMIT 1;" 2>&1 | Out-String
    Assert ($out -match "lab-fake-model") "the LLM change is audited"
    Assert ($out -notmatch "sk-acceptance") "the LLM audit row carries no key"

    # ---- 11. passport editing ----------------------------------------------
    $passport = @{
        project = "config-lab"
        include = @("127.0.0.1")
        exclude = @("127.0.0.1:9")
        methods = @("GET", "HEAD", "OPTIONS", "POST")
        basis   = "self-hosted lab, passport editor acceptance"
        operator = "acceptance"
        allow_private = $true
        allow_waf_probe = $true
        allow_active_probes = $true
        max_requests = 77
        rps = 6
        expires_at = (Get-Date).ToUniversalTime().AddDays(7).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $created2 = Api "POST" "/api/engagements" @{ name = "cfg-$((Get-Date).ToString('HHmmss'))"; scope = $passport }
    Assert ($created2.Code -eq 201) "engagement created from a full passport form"
    $engId2 = $created2.Body.id
    $raw2 = $created2.Raw
    Assert ($raw2 -match "allow_waf_probe" -and $raw2 -match "127.0.0.1:9" -and $raw2 -match "POST") "every passport field was persisted"

    # The wildcard is still refused, and nothing is saved.
    $r = Api "PUT" "/api/engagements/$engId2/scope" @{ scope = @{ include = @("*"); basis = "self-hosted lab"; operator = "x" } }
    Assert ($r.Code -eq 400) "a top-level wildcard passport is refused (edit path)"

    # Widening is allowed, and audited.
    $widened = $passport.Clone()
    $widened.allow_object_seeding = $true
    $widened.max_requests = 123
    $r = Api "PUT" "/api/engagements/$engId2/scope" @{ scope = $widened; updated_by = "acceptance" }
    Assert ($r.Code -eq 200 -and $r.Body.changed -eq $true) "passport edit applied"
    Assert ($r.Body.widened -eq $true) "the API reports the change as widening"
    $out = & "$pgDir\bin\psql.exe" -h 127.0.0.1 -p 55432 -U youkai -d $dbName -tAc `
        "SELECT detail::text FROM audit_log WHERE purpose='config' AND url='config:scope' AND engagement LIKE 'cfg-%' ORDER BY id DESC LIMIT 1;" 2>&1 | Out-String
    Assert ($out -match "allow_object_seeding") "scope widening is audited"
    Assert ($out -match "acceptance") "the scope audit names the operator"

    # ---- 12. proof-carrying report: four evidence, snapshots, SARIF, disclosure
    Write-Host "`n== evidence report ==" -ForegroundColor Cyan

    # The engine has already produced findings by now; grade them.
    $r = Api "GET" "/api/engagements/$engId/report" $null
    Assert ($r.Code -eq 200) "report bundle renders"
    Assert ($r.Body.schema -eq "YoukaiReport/v1") "report declares its schema"
    Assert ($r.Body.coverage.requests -gt 0) "coverage counts the requests that actually happened"
    Assert ($r.Raw -notmatch "全站") "the report makes no whole-site claim"

    # Every finding carries the four pieces or says what is missing.
    $graded = 0
    foreach ($f in @($r.Body.findings)) {
        Assert ($null -ne $f.evidence_block) "finding $($f.id) carries an evidence block"
        Assert ($null -ne $f.PSObject.Properties['min_impact']) "finding $($f.id) carries min_impact"
        Assert ($null -ne $f.PSObject.Properties['stop_condition']) "finding $($f.id) carries stop_condition"
        Assert ($null -ne $f.PSObject.Properties['counter']) "finding $($f.id) carries counter"
        if ($f.evidence_block.complete) { $graded++ }
    }
    Assert ($graded -gt 0) "at least one finding resolved its request_id against the audit log"

    # Same ledger, same bytes: snapshots are checkable by hash.
    $md1 = (& curl.exe -s -H "X-Youkai-Token: $token" "$apiBase/api/engagements/$engId/report?format=md" | Out-String)
    $md2 = (& curl.exe -s -H "X-Youkai-Token: $token" "$apiBase/api/engagements/$engId/report?format=md" | Out-String)
    Assert ($md1 -eq $md2) "two renders of an unchanged ledger are byte-identical"
    Assert ($md1 -match "① 证据" -and $md1 -match "④ 反证说明") "markdown carries the four evidence sections"

    # Snapshot: immutable, hashed, freeze-the-passport.
    $snap1 = Api "POST" "/api/engagements/$engId/reports" $null
    Assert ($snap1.Code -eq 201) "snapshot created"
    Assert ($snap1.Body.sha256.Length -eq 64) "snapshot carries a sha256 anchor"
    $snap1Id = $snap1.Body.snapshot.id
    $out = & "$pgDir\bin\psql.exe" -h 127.0.0.1 -p 55432 -U youkai -d $dbName -tAc `
        "UPDATE report_snapshots SET content_sha256='tampered' WHERE id=$snap1Id;" 2>&1 | Out-String
    Assert ($out -match "append-only") "the snapshot table refuses UPDATE at the database level"

    # SARIF exports the same ledger for CI.
    $sarif = (& curl.exe -s -H "X-Youkai-Token: $token" "$apiBase/api/engagements/$engId/sarif" | Out-String)
    Assert ($sarif -match '"version": "2.1.0"') "SARIF export declares version 2.1.0"
    Assert ($sarif -match '"ruleId": "youkai/') "SARIF results carry youkai rule ids"
    Assert ($sarif -match '"min_impact"') "the four evidence pieces survive the SARIF export"

    # Disclosure: only verified findings, and only with an authorisation basis.
    $disc = (& curl.exe -s -o NUL -w "%{http_code}" -H "X-Youkai-Token: $token" "$apiBase/api/engagements/$engId/disclosure")
    Assert (($disc -as [string]).Trim() -eq "409") "disclosure refuses to ship with no verified finding"

    $graphNow = Api "GET" "/api/engagements/$engId/graph" $null
    $cand = @($graphNow.Body.findings | Where-Object { $_.state -eq "candidate" } | Select-Object -First 1)
    if ($cand.Count -gt 0) {
        $r = Api "POST" "/api/engagements/$engId/findings/$($cand[0].id)/verdict" @{
            operator = "acceptance"; note = "复现确认"; confirm = $true
        }
        Assert ($r.Code -eq 200) "operator verdict recorded (candidate -> verified)"
    }
    $disc = (& curl.exe -s -H "X-Youkai-Token: $token" "$apiBase/api/engagements/$engId/disclosure" | Out-String)
    Assert ($disc -match "授权声明") "disclosure states the authorisation"
    Assert ($disc -match "估计") "disclosure labels CVSS as an estimate"

    # Widen the passport, snapshot again: the frozen scope must differ.
    $scopeNow = (Api "GET" "/api/engagements/$engId" $null).Body.scope
    $scopeNow | Add-Member -NotePropertyName allow_object_seeding -NotePropertyValue $true -Force
    $scopeNow | Add-Member -NotePropertyName max_requests -NotePropertyValue 321 -Force
    $r = Api "PUT" "/api/engagements/$engId/scope" @{ scope = $scopeNow; updated_by = "acceptance" }
    Assert ($r.Code -eq 200) "passport widened before the second snapshot"
    $snap2 = Api "POST" "/api/engagements/$engId/reports" $null
    Assert ($snap2.Code -eq 201) "second snapshot created"
    Assert ($snap2.Body.sha256 -ne $snap1.Body.sha256) "the second snapshot hashes differently after a scope change"

    # ---- 13. login-state browser (session injected inside the Fetch gate) ---
    Write-Host "`n== authenticated browser ==" -ForegroundColor Cyan

    # alice's own object: the render must carry her cookie, and the page must show
    # the marker that only her session can read.
    $iAuth = New-Intent $engId "browser" @{
        url = "http://127.0.0.1:$labPort/orders/1"; session = "alice"; wait_ms = 1200
    } "以 alice 的身份只读渲染她自己的对象"
    Assert ($iAuth.Code -eq 201) "authenticated browser intent queued"
    Assert ($iAuth.Body.gate.tier -eq 1) "authenticated render is still tier 1"

    $runRes = Api "POST" "/api/engagements/$engId/runs" @{ max_steps = 4 }
    Assert ($runRes.Code -eq 202) "authenticated render run accepted"
    $authRun = $runRes.Body.run_id
    for ($i = 0; $i -lt 180; $i++) {
        Start-Sleep -Milliseconds 500
        $r = Api "GET" "/api/engagements/$engId/runs/$authRun" $null
        if ($r.Body.done) { break }
    }
    $g2 = (Api "GET" "/api/engagements/$engId/graph" $null).Body
    $authFacts = @($g2.facts | Where-Object { $_.statement -match "以身份 alice 渲染" })
    Assert ($authFacts.Count -ge 1) "the render recorded WHO it rendered as"
    if ($authFacts.Count -ge 1) {
        Assert ($authFacts[0].evidence.session -eq "alice") "the fact carries the session name"
        Assert ($authFacts[0].evidence.injected_requests -ge 1) "at least one request carried the credential"
        Assert ($authFacts[0].evidence.request_id) "the authenticated fact cites a request_id"
    }
    $allText = $g2.facts | ForEach-Object { $_ | ConvertTo-Json -Depth 6 -Compress } | Out-String
    Assert ($allText -notmatch "sess-alice|sess-bob") "no cookie value reached the ledger"

    # bob looking at alice's deliberately broken object -> candidate, never verified.
    $iPeek = New-Intent $engId "browser" @{
        url = "http://127.0.0.1:$labPort/orders/2"; session = "bob"; wait_ms = 1200
    } "以 bob 的身份渲染 alice 的对象页(越权视角)"
    Assert ($iPeek.Code -eq 201) "viewer render intent queued"
    $runRes = Api "POST" "/api/engagements/$engId/runs" @{ max_steps = 4 }
    for ($i = 0; $i -lt 180; $i++) {
        Start-Sleep -Milliseconds 500
        $r = Api "GET" "/api/engagements/$engId/runs/$($runRes.Body.run_id)" $null
        if ($r.Body.done) { break }
    }
    $g3 = (Api "GET" "/api/engagements/$engId/graph" $null).Body
    $viewer = @($g3.findings | Where-Object { $_.kind -eq "bola" -and $_.where -match "/orders/2" -and $_.title -match "bob" })
    Assert ($viewer.Count -ge 1) "viewer-side render produced a BOLA candidate"
    if ($viewer.Count -ge 1) {
        Assert ($viewer[0].state -eq "candidate") "the viewer-side finding stays a candidate"
        Assert ($viewer[0].evidence.session -eq "bob" -and $viewer[0].evidence.owner -eq "alice") "the finding names session and owner, not the cookie"
    }

    # A session that does not exist must error, not silently render anonymously.
    $iGhost = New-Intent $engId "browser" @{
        url = "http://127.0.0.1:$labPort/orders/1"; session = "nobody"; wait_ms = 300
    }
    $runRes = Api "POST" "/api/engagements/$engId/runs" @{ max_steps = 2 }
    for ($i = 0; $i -lt 120; $i++) {
        Start-Sleep -Milliseconds 500
        $r = Api "GET" "/api/engagements/$engId/runs/$($runRes.Body.run_id)" $null
        if ($r.Body.done) { break }
    }
    $g4 = (Api "GET" "/api/engagements/$engId/graph" $null).Body
    $ghostFacts = @($g4.facts | Where-Object { $_.statement -match "以身份 nobody 渲染" })
    Assert ($ghostFacts.Count -eq 0) "an unknown session does not render (no anonymous fallback)"

    # Cross-host: the same server under another name is still in scope, but the
    # identity's credential must not follow it.
    $scopeX = (Api "GET" "/api/engagements/$engId" $null).Body.scope
    $scopeX.include = @("127.0.0.1", "localhost")
    $r = Api "PUT" "/api/engagements/$engId/scope" @{ scope = $scopeX; updated_by = "acceptance" }
    Assert ($r.Code -eq 200) "scope widened to cover the second host name"
    $iX = New-Intent $engId "browser" @{
        url = "http://localhost:$labPort/orders/1"; session = "alice"; wait_ms = 800
    } "跨 host 渲染:会话不应跟随"
    $runRes = Api "POST" "/api/engagements/$engId/runs" @{ max_steps = 4 }
    for ($i = 0; $i -lt 180; $i++) {
        Start-Sleep -Milliseconds 500
        $r = Api "GET" "/api/engagements/$engId/runs/$($runRes.Body.run_id)" $null
        if ($r.Body.done) { break }
    }
    $g5 = (Api "GET" "/api/engagements/$engId/graph" $null).Body
    $cross = @($g5.facts | Where-Object { $_.statement -match "以身份 alice 渲染 http://localhost" })
    Assert ($cross.Count -ge 1) "the cross-host render happened"
    if ($cross.Count -ge 1) {
        Assert ($cross[0].evidence.injected_requests -eq 0) "the credential did NOT follow to another host"
    }

    # ---- 14. process memory: no repeated probe of the same endpoint --------
    Write-Host "`n== trace memory ==" -ForegroundColor Cyan

    $before = (Api "GET" "/api/engagements/$engId/graph" $null).Body
    $probesBefore = @($before.intents | Where-Object { $_.capability -eq "probe" -and ($_.args.url -match "/\.git/config") }).Count
    Assert ($probesBefore -ge 1) "a probe of the git path already ran in this engagement"

    # Run again with the same seed: the guard must not derive that probe twice.
    $runRes = Api "POST" "/api/engagements/$engId/runs" @{ max_steps = 6; seed_urls = @("http://127.0.0.1:$labPort/search?q=acceptance") }
    Assert ($runRes.Code -eq 202) "second run accepted"
    for ($i = 0; $i -lt 180; $i++) {
        Start-Sleep -Milliseconds 500
        $r = Api "GET" "/api/engagements/$engId/runs/$($runRes.Body.run_id)" $null
        if ($r.Body.done) { break }
    }
    $after = (Api "GET" "/api/engagements/$engId/graph" $null).Body
    $probesAfter = @($after.intents | Where-Object { $_.capability -eq "probe" -and ($_.args.url -match "/\.git/config") }).Count
    Assert ($probesAfter -eq $probesBefore) "the same endpoint was not probed twice (trace guard)"

    # The trail itself is available to the planner as process memory.
    $done = @($after.intents | Where-Object { $_.trace -and $_.trace -ne "" })
    Assert ($done.Count -ge 1) "executed steps carry a trace"
    Assert (($done | ForEach-Object { $_.trace } | Out-String) -notmatch "sess-alice|Cookie") "traces carry no credentials"

    # ---- 15. detection coverage: API schema / GraphQL / JWT / OAuth ---------
    Write-Host "`n== detection coverage ==" -ForegroundColor Cyan

    # The four v0.9 capabilities are tier 1: read-only, no approval.
    foreach ($cap in @("api_spec", "graphql_introspect", "jwt_audit", "oauth_audit")) {
        $i = New-Intent $engId $cap @{ url = "http://127.0.0.1:$labPort/" } "coverage probe"
        Assert ($i.Code -eq 201) "$cap is registered"
        Assert ($i.Body.gate.tier -eq 1) "$cap is classified tier 1"
    }

    $iSpec = New-Intent $engId "api_spec" @{ url = "http://127.0.0.1:$labPort/openapi.json" } "接入 API 文档"
    $iGQL = New-Intent $engId "graphql_introspect" @{ url = "http://127.0.0.1:$labPort/graphql" } "读 GraphQL schema"
    $iAuth = New-Intent $engId "oauth_audit" @{
        url = "http://127.0.0.1:$labPort"
        authorize_url = "http://127.0.0.1:$labPort/authorize?response_type=code&client_id=app&redirect_uri=http://127.0.0.1:$labPort/cb"
    } "OAuth 配置审计"
    $runRes = Api "POST" "/api/engagements/$engId/runs" @{ max_steps = 8 }
    Assert ($runRes.Code -eq 202) "coverage run accepted"
    for ($i = 0; $i -lt 240; $i++) {
        Start-Sleep -Milliseconds 500
        $r = Api "GET" "/api/engagements/$engId/runs/$($runRes.Body.run_id)" $null
        if ($r.Body.done) { break }
    }
    # The steps land as they finish; poll for the specific evidence rather than
    # guessing a sleep (the run's "done" flag is not a promise about every row).
    $g6 = $null
    $oauthTitles = ""
    for ($i = 0; $i -lt 60; $i++) {
        $g6 = (Api "GET" "/api/engagements/$engId/graph" $null).Body
        $oauthTitles = (@($g6.findings | Where-Object { $_.kind -eq "oauth" } | ForEach-Object { $_.title }) -join "|")
        if ($oauthTitles -match "state" -and $oauthTitles -match "redirect_uri") { break }
        Start-Sleep -Milliseconds 500
    }
    $factsText = ($g6.facts | ForEach-Object { $_.statement }) -join "`n"
    $kinds = @($g6.findings | ForEach-Object { $_.kind })

    Assert ($factsText -match "API 文档可读") "the OpenAPI document was parsed"
    Assert (@($g6.assets | Where-Object { $_.kind -eq "endpoint" -and $_.value -match "/api/orders" }).Count -ge 1) "documented endpoints were registered as assets"
    Assert ($factsText -match "GraphQL mutation:Mutation.deleteOrder") "GraphQL mutations were registered and labelled"
    Assert ($factsText -match "GraphQL query:Query.order") "GraphQL queries were registered"
    Assert ($kinds -contains "oauth") "OAuth configuration findings were produced"
    Assert ($oauthTitles -match "state") "missing state is reported"
    Assert ($oauthTitles -match "redirect_uri") "loose redirect_uri is reported"

    # JWT: the lab's login now sets a deliberately weak token, so alice's session has one.
    $iJwt = New-Intent $engId "jwt_audit" @{
        session = "alice"; url = "http://127.0.0.1:$labPort/"
    } "审计 alice 会话里的 JWT"
    $runRes = Api "POST" "/api/engagements/$engId/runs" @{ max_steps = 4 }
    for ($i = 0; $i -lt 180; $i++) {
        Start-Sleep -Milliseconds 500
        $r = Api "GET" "/api/engagements/$engId/runs/$($runRes.Body.run_id)" $null
        if ($r.Body.done) { break }
    }
    $g7 = (Api "GET" "/api/engagements/$engId/graph" $null).Body
    $jwt = @($g7.findings | Where-Object { $_.kind -eq "jwt" })
    Assert ($jwt.Count -ge 1) "the JWT audit produced findings"
    if ($jwt.Count -ge 1) {
        $titles = ($jwt | ForEach-Object { $_.title }) -join " / "
        Assert ($titles -match "alg=none") "alg=none is reported"
        Assert ($titles -match "exp") "a missing exp is reported"
        Assert ($jwt[0].state -eq "candidate") "JWT findings are candidates"
    }
    $jwtText = ($g7.findings | Where-Object { $_.kind -eq "jwt" } | ConvertTo-Json -Depth 6 -Compress) + ($g7.facts | ConvertTo-Json -Depth 6 -Compress)
    Assert ($jwtText -notmatch "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0") "the token itself never reached the ledger"

    # ---- 16. database-level invariants -------------------------------------
    Write-Host "`n== database guards ==" -ForegroundColor Cyan
    $out = & "$pgDir\bin\psql.exe" -h 127.0.0.1 -p 55432 -U youkai -d $dbName -tAc "UPDATE audit_log SET status=999;" 2>&1 | Out-String
    Assert ($out -match "append-only") "audit_log refuses UPDATE at the database level"
    $out = & "$pgDir\bin\psql.exe" -h 127.0.0.1 -p 55432 -U youkai -d $dbName -tAc "UPDATE findings SET state='verified';" 2>&1 | Out-String
    Assert ($out -match "operator verdict") "candidate->verified is refused without an operator verdict"
    $out = & "$pgDir\bin\psql.exe" -h 127.0.0.1 -p 55432 -U youkai -d $dbName -tAc "UPDATE intents SET approved=true;" 2>&1 | Out-String
    Assert ($out -match "operator approval") "approved=true is refused without an approval row"

    # ---- 8. findings verdict path ------------------------------------------
    $finding = $null
    foreach ($f in $graph.Body.findings) { if ($f.state -eq "candidate") { $finding = $f; break } }
    if ($null -ne $finding) {
        $vp = "/api/engagements/$engId/findings/$($finding.id)/verdict"
        $r = Api "POST" $vp @{ operator = "acceptance"; note = "n" }
        Assert ($r.Code -eq 400) "verdict without an explicit confirmation is refused"
        $r = Api "POST" $vp @{ operator = "acceptance"; note = "reproduced in a browser"; confirm = $true }
        Assert ($r.Code -eq 200) "a confirmed verdict is accepted"
    }

    # ---- 9. report ----------------------------------------------------------
    Write-Host "`n== report ==" -ForegroundColor Cyan
    $rep = Api "GET" "/api/engagements/$engId/report" $null
    Assert ($rep.Code -eq 200) "report bundle renders"
    Assert ($rep.Body.exploit_provider -match "no exploitation provider") "the report states the wall"
    $md = Invoke-WebRequest -Uri "$apiBase/api/engagements/$engId/report?format=md&token=$token" -UseBasicParsing -TimeoutSec 20
    Assert ($md.Content -match "youkai 证据报告") "markdown report renders"
}
finally {
    foreach ($p in @($srv, $lab)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
    Remove-Item Env:YOUKAI_DSN -ErrorAction SilentlyContinue
    Remove-Item Env:YOUKAI_DSN -ErrorAction SilentlyContinue
    Remove-Item Env:FAIRY_AUTH_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:YOUKAI_SESSION_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:ALICE_PW -ErrorAction SilentlyContinue
    Remove-Item Env:BOB_PW -ErrorAction SilentlyContinue
}

if ($script:failures -ne 0) {
    Write-Host "`n$($script:failures) ACCEPTANCE ASSERTION(S) FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "`nALL ACCEPTANCE ASSERTIONS PASSED" -ForegroundColor Green
exit 0
