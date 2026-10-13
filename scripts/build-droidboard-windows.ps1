param([string]$Python = "py")
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Venv = Join-Path $Root ".venv-desktop"

function Invoke-Checked {
    param([string]$Command, [string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed ($LASTEXITCODE): $Command $Arguments" }
}

Push-Location $Root
try {
    if ($env:OS -ne "Windows_NT") { throw "Build this package on Windows." }
    if ($Python -eq "py") {
        Invoke-Checked $Python @("-3.12", "-m", "venv", $Venv)
    } else {
        Invoke-Checked $Python @("-m", "venv", $Venv)
    }
    $VenvPython = Join-Path $Venv "Scripts\python.exe"
    Invoke-Checked $VenvPython @("-c", "import struct, sys; assert sys.version_info[:2] == (3, 12) and struct.calcsize('P') == 8, 'Use Python 3.12 x64'")
    Invoke-Checked $VenvPython @("-m", "pip", "install", "--upgrade", "pip")
    Invoke-Checked $VenvPython @("-m", "pip", "install", ".[desktop]", "pyinstaller>=6.14,<7")
    Invoke-Checked $VenvPython @("-m", "PyInstaller", "--noconfirm", "--clean", "packaging\droidboard.spec")
    Compress-Archive -Path "dist\Droidboard" -DestinationPath "dist\Droidboard-windows-x64.zip" -Force
    Write-Host "Ready: dist\Droidboard\Droidboard.exe and dist\Droidboard-windows-x64.zip"
} finally {
    Pop-Location
}
