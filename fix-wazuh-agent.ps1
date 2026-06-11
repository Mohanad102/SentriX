# Fix Wazuh Agent - Auto-detect WSL2 IP and update config
# Run as Administrator at startup or after network change

$wslIP = (wsl -- ip addr show eth0 2>$null) -match "inet " | ForEach-Object {
    if ($_ -match "inet (\d+\.\d+\.\d+\.\d+)") { $matches[1] }
} | Select-Object -First 1

if (-not $wslIP) {
    Write-Host "ERROR: Could not get WSL2 IP" -ForegroundColor Red
    exit 1
}

Write-Host "WSL2 IP: $wslIP" -ForegroundColor Cyan

NET STOP WazuhSvc 2>$null
Start-Sleep -Seconds 2

$conf = Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" -Raw
$conf = $conf -replace '<address>.*?</address>', "<address>$wslIP</address>"
Set-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" -Value $conf -Encoding UTF8

NET START WazuhSvc
Write-Host "Wazuh Agent updated to $wslIP and restarted" -ForegroundColor Green
