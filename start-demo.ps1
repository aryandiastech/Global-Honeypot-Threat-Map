# One-click local demo (Windows PowerShell). No AWS account needed.
#   - starts the demo backend on http://localhost:8000 (press Start in the dashboard for live attacks)
#   - starts the React dashboard on http://localhost:5173 and opens it
# Usage:  right-click > Run with PowerShell   or   powershell -ExecutionPolicy Bypass -File .\start-demo.ps1
# Optional: .\start-demo.ps1 -WithCowrie   (also tails a real Cowrie honeypot started with docker compose)
param([switch]$WithCowrie)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Need($cmd, $hint) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Write-Host "Missing: $cmd  ->  $hint" -ForegroundColor Red; exit 1 }
}
$py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { $null }
if (-not $py) { Write-Host "Missing: Python 3.10+  ->  https://www.python.org/downloads/ (tick 'Add to PATH')" -ForegroundColor Red; exit 1 }
Need "npm" "Install Node.js LTS from https://nodejs.org/"

if (-not (Test-Path "frontend/.env")) {
  Copy-Item "frontend/.env.example" "frontend/.env"
  Write-Host "Created frontend/.env (no keys needed)." -ForegroundColor Green
}
if (-not (Test-Path "frontend/node_modules")) {
  Write-Host "Installing dashboard dependencies (first run only)..."
  npm --prefix frontend install
}

$backendArgs = @("demo/server.py")
if ($WithCowrie) { $backendArgs += @("--cowrie-log", "honeypots/cowrie/logs/cowrie.json") }
$backend = Start-Process -FilePath $py -ArgumentList $backendArgs -PassThru -NoNewWindow
Start-Sleep -Seconds 2
Write-Host "Backend: http://localhost:8000/events?limit=5" -ForegroundColor Green
try {
  # --open launches the browser once Vite is ready
  npm --prefix frontend run dev -- --open
} finally {
  if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id -Force }
}
