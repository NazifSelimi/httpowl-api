# HTTPowl agent installer for Windows (IIS). Run in an elevated PowerShell:
#   $env:HTTPOWL_TOKEN="owl_..."; iwr -useb https://httpowl.net/install.ps1 | iex
$ErrorActionPreference = "Stop"
$server = if ($env:HTTPOWL_SERVER) { $env:HTTPOWL_SERVER } else { "https://httpowl.net" }
$token = $env:HTTPOWL_TOKEN
if ($token -notmatch '^owl_[A-Za-z0-9_-]{43}$') { throw "Set `$env:HTTPOWL_TOKEN to the token from your HTTPowl site page first." }
$dir = "C:\Program Files\HTTPowl"; $data = "C:\ProgramData\HTTPowl"
New-Item -ItemType Directory -Force -Path $dir, $data | Out-Null
$exe = Join-Path $dir "httpowl-agent.exe"
Invoke-WebRequest "$server/dl/httpowl-agent-windows-amd64.exe" -OutFile "$exe.new"
$sums = (Invoke-WebRequest "$server/dl/SHA256SUMS" -UseBasicParsing).Content
$want = ($sums -split "`n" | Where-Object { $_ -match "httpowl-agent-windows-amd64.exe$" }) -split '\s+' | Select-Object -First 1
if ((Get-FileHash "$exe.new" -Algorithm SHA256).Hash.ToLower() -ne $want) { throw "Checksum mismatch, try again." }
if (Get-Service httpowl-agent -ErrorAction SilentlyContinue) { Stop-Service httpowl-agent; sc.exe delete httpowl-agent | Out-Null; Start-Sleep 2 }
Move-Item -Force "$exe.new" $exe
@{ server = $server; token = $token; logs = @("auto"); firewall = "auto"; state_dir = $data } | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $data "agent.json")
icacls $data /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
New-Service -Name httpowl-agent -BinaryPathName "`"$exe`" -config `"$data\agent.json`"" -DisplayName "HTTPowl agent" -StartupType Automatic | Out-Null
Start-Service httpowl-agent
Write-Host "HTTPowl agent installed and running."
