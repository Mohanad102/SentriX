# SentriX Auto-Connect Script
# Reads bore tunnel ports from SentriX server and updates Wazuh agent config automatically.
# Run this script once after every server restart, or schedule it as a Windows Task.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File SentriX-AutoConnect.ps1
#
# To schedule it to run every 5 minutes (so agent reconnects automatically):
#   schtasks /create /tn "SentriX-AutoConnect" /tr "powershell -ExecutionPolicy Bypass -File C:\SentriX-AutoConnect.ps1" /sc minute /mo 5 /ru SYSTEM /f

param(
    [string]$SentriXUrl = "https://miniature-space-capybara-w65p479x5pgcwjw-8000.app.github.dev",
    [string]$SentriXUser = "admin",
    [string]$SentriXPass = "admin123",
    [string]$OssecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
)

$ErrorActionPreference = "Stop"

Write-Host "=== SentriX Auto-Connect ===" -ForegroundColor Cyan

# ── Step 1: Get JWT token ──────────────────────────────────────────────────────
Write-Host "Authenticating with SentriX..."
try {
    $loginBody = @{ username = $SentriXUser; password = $SentriXPass } | ConvertTo-Json
    $loginResp = Invoke-RestMethod -Uri "$SentriXUrl/api/auth/login" `
        -Method POST -Body $loginBody -ContentType "application/json" -SkipCertificateCheck
    $token = $loginResp.access_token
    Write-Host "  Authenticated." -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Could not authenticate with SentriX: $_" -ForegroundColor Red
    exit 1
}

# ── Step 2: Get tunnel info ────────────────────────────────────────────────────
Write-Host "Fetching bore tunnel ports..."
try {
    $headers = @{ Authorization = "Bearer $token" }
    $tunnelResp = Invoke-RestMethod -Uri "$SentriXUrl/api/agents/tunnel-info" `
        -Method GET -Headers $headers -SkipCertificateCheck
    $host_addr = $tunnelResp.host
    $port_1514 = $tunnelResp.port_1514
    $port_1515 = $tunnelResp.port_1515
    Write-Host "  Tunnel: ${host_addr}:${port_1514} (events) / ${host_addr}:${port_1515} (enroll)" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Could not get tunnel info: $_" -ForegroundColor Red
    Write-Host "  Is the SentriX server running? Did bore tunnels start successfully?" -ForegroundColor Yellow
    exit 1
}

# ── Step 3: Read current ossec.conf ───────────────────────────────────────────
Write-Host "Reading $OssecConf ..."
if (-not (Test-Path $OssecConf)) {
    Write-Host "  ERROR: ossec.conf not found at $OssecConf" -ForegroundColor Red
    exit 1
}
$content = Get-Content $OssecConf -Raw

# ── Step 4: Check if update is needed ─────────────────────────────────────────
$alreadyCorrect = $content -match [regex]::Escape("<address>$host_addr</address>") -and
                  $content -match [regex]::Escape("<port>$port_1514</port>")

if ($alreadyCorrect) {
    Write-Host "  Config already up to date — no changes needed." -ForegroundColor Green
} else {
    # ── Step 5: Replace server address and port ──────────────────────────────
    Write-Host "  Updating server address to $host_addr ..."
    $newContent = $content -replace '(?s)(<server>.*?<address>)[^<]*(</address>)', "`${1}$host_addr`${2}"
    $newContent = $newContent -replace '(?s)(<server>.*?<port>)[^<]*(</port>)', "`${1}$port_1514`${2}"

    # Backup original
    $backupPath = "$OssecConf.bak"
    Copy-Item $OssecConf $backupPath -Force
    Write-Host "  Backup saved to $backupPath" -ForegroundColor DarkGray

    # Write new config (requires admin)
    try {
        Set-Content $OssecConf $newContent -Encoding UTF8
        Write-Host "  ossec.conf updated successfully." -ForegroundColor Green
    } catch {
        Write-Host "  ERROR writing ossec.conf — run this script as Administrator: $_" -ForegroundColor Red
        exit 1
    }
}

# ── Step 6: Restart Wazuh agent service ───────────────────────────────────────
Write-Host "Restarting WazuhSvc..."
try {
    $svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "  WazuhSvc not found — is Wazuh agent installed?" -ForegroundColor Yellow
    } else {
        Restart-Service -Name "WazuhSvc" -Force
        Start-Sleep -Seconds 3
        $svc.Refresh()
        Write-Host "  WazuhSvc status: $($svc.Status)" -ForegroundColor Green
    }
} catch {
    Write-Host "  ERROR restarting WazuhSvc: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Done! Your agent should reconnect to SentriX shortly." -ForegroundColor Cyan
Write-Host "Check the Agents page in SentriX to confirm status changes to Active."
