param(
    [string]$Python = "py",
    [string]$InnoSetup = "",
    [string]$CertificatePath = "",
    [string]$TimestampUrl = "",
    [string]$SignTool = ""
)
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Venv = Join-Path $Root ".venv-desktop"
$InstallerWork = Join-Path $Root "build\installer"
$WebView2Bootstrapper = Join-Path $InstallerWork "MicrosoftEdgeWebview2Setup.exe"
$WebView2BootstrapperUrl = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"

function Invoke-Checked {
    param([string]$Command, [string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed ($LASTEXITCODE): $Command $Arguments" }
}

function Find-InnoSetup {
    if ($InnoSetup) {
        if (-not (Test-Path -LiteralPath $InnoSetup -PathType Leaf)) {
            throw "Inno Setup compiler not found: $InnoSetup"
        }
        return (Resolve-Path -LiteralPath $InnoSetup).Path
    }

    $Command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    $Candidates = @(@(
            $(if ($Command) { $Command.Source }),
            "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) })
    if (-not $Candidates) {
        throw "Inno Setup 6 is required. Install it or pass -InnoSetup C:\path\to\ISCC.exe"
    }
    return $Candidates[0]
}

function Find-SignTool {
    if ($SignTool) {
        if (-not (Test-Path -LiteralPath $SignTool -PathType Leaf)) {
            throw "SignTool not found: $SignTool"
        }
        return (Resolve-Path -LiteralPath $SignTool).Path
    }

    $Command = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    $SdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $SdkCandidates = @()
    if (Test-Path -LiteralPath $SdkRoot -PathType Container) {
        $SdkCandidates = @(Get-ChildItem -LiteralPath $SdkRoot -Filter "signtool.exe" -Recurse -File |
            Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
            Sort-Object LastWriteTime -Descending |
            ForEach-Object { $_.FullName })
    }
    $Candidates = @(@($(if ($Command) { $Command.Source })) + $SdkCandidates |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) })
    if (-not $Candidates) {
        throw "SignTool is required for signing. Install the Windows SDK or pass -SignTool C:\path\to\signtool.exe"
    }
    return $Candidates[0]
}

function Invoke-SignFile {
    param(
        [string]$SignToolPath,
        [string]$PfxPath,
        [string]$Rfc3161TimestampUrl,
        [string]$FilePath
    )
    $SignArguments = @(
        "sign", "/fd", "SHA256", "/tr", $Rfc3161TimestampUrl, "/td", "SHA256",
        "/f", $PfxPath
    )
    if ($env:DROIDBOARD_SIGNING_PASSWORD) {
        $SignArguments += @("/p", $env:DROIDBOARD_SIGNING_PASSWORD)
    }
    $SignArguments += $FilePath
    & $SignToolPath @SignArguments
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed for: $FilePath" }
    & $SignToolPath "verify" "/pa" "/v" "/tw" $FilePath
    if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed for: $FilePath" }
}

Push-Location $Root
try {
    if ($env:OS -ne "Windows_NT") { throw "Build this package on Windows." }
    $ResolvedCertificate = ""
    $SignToolPath = ""
    if ($CertificatePath) {
        if (-not $TimestampUrl) { throw "Pass -TimestampUrl when -CertificatePath is used." }
        if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
            throw "PFX certificate not found: $CertificatePath"
        }
        $ResolvedCertificate = (Resolve-Path -LiteralPath $CertificatePath).Path
        $SignToolPath = Find-SignTool
    }
    if ($Python -eq "py") {
        Invoke-Checked $Python @("-3.12", "-m", "venv", "--clear", $Venv)
    } else {
        Invoke-Checked $Python @("-m", "venv", "--clear", $Venv)
    }
    $VenvPython = Join-Path $Venv "Scripts\python.exe"
    Invoke-Checked $VenvPython @("-c", "import struct, sys; assert sys.version_info[:2] == (3, 12) and struct.calcsize('P') == 8, 'Use Python 3.12 x64'")
    Invoke-Checked $VenvPython @("-m", "pip", "install", "--upgrade", "pip")
    Invoke-Checked $VenvPython @("-m", "pip", "install", ".[desktop]", "pyinstaller>=6.14,<7")
    Invoke-Checked $VenvPython @("-m", "PyInstaller", "--noconfirm", "--clean", "packaging\droidboard.spec")
    if ($ResolvedCertificate) {
        Invoke-SignFile $SignToolPath $ResolvedCertificate $TimestampUrl (Join-Path $Root "dist\Droidboard\Droidboard.exe")
    }

    New-Item -ItemType Directory -Path $InstallerWork -Force | Out-Null
    Invoke-WebRequest -Uri $WebView2BootstrapperUrl -OutFile $WebView2Bootstrapper
    $Signature = Get-AuthenticodeSignature -LiteralPath $WebView2Bootstrapper
    if ($Signature.Status -ne "Valid" -or $Signature.SignerCertificate.Subject -notmatch "Microsoft Corporation") {
        throw "The downloaded WebView2 bootstrapper does not have a valid Microsoft signature."
    }

    $AppVersion = (& $VenvPython -c "import importlib.metadata; print(importlib.metadata.version('arkadroid'))").Trim()
    if ($LASTEXITCODE -ne 0 -or -not $AppVersion) { throw "Unable to determine the application version." }
    $Iscc = Find-InnoSetup
    Invoke-Checked $Iscc @("/DAppVersion=$AppVersion", "packaging\droidboard-installer.iss")
    if ($ResolvedCertificate) {
        Invoke-SignFile $SignToolPath $ResolvedCertificate $TimestampUrl (Join-Path $Root "dist\Droidboard-Setup-windows-x64.exe")
    }
    Write-Host "Ready: dist\Droidboard-Setup-windows-x64.exe"
} finally {
    Pop-Location
}
