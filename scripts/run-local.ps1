$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$projectTemp = Join-Path $projectRoot '.tmp'
New-Item -ItemType Directory -Path $projectTemp -Force | Out-Null
$env:TEMP = $projectTemp
$env:TMP = $projectTemp
$env:PIP_CACHE_DIR = Join-Path $projectTemp 'pip-cache'

$pythonExe = $null
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCommand -and $pythonCommand.Source -notmatch '\\WindowsApps\\python\.exe$') {
    $pythonExe = $pythonCommand.Source
}
if (-not $pythonExe -and $env:LOCALAPPDATA) {
    $pythonRoot = Join-Path $env:LOCALAPPDATA 'Programs\Python'
    $pythonExe = Get-ChildItem -Path $pythonRoot -Directory -Filter 'Python3*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName 'python.exe' } |
        Where-Object { Test-Path $_ } |
        Select-Object -First 1
}
if (-not $pythonExe) {
    throw 'Python 3.11 or newer is required. Install Python, then reopen VS Code.'
}
$pythonVersionText = & $pythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0) { throw 'Python could not be started.' }
if ([version]$pythonVersionText.Trim() -lt [version]'3.11') {
    throw 'Python 3.11 or newer is required.'
}

if (-not (Test-Path '.venv\Scripts\python.exe')) {
    & $pythonExe -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python virtual environment.' }
}
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
& $venvPython -m pip install -q -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }

if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
    Write-Host 'Created .env from .env.example. Set a unique SECRET_KEY before external deployment.' -ForegroundColor Yellow
}

& $venvPython -m uvicorn app.main:app
