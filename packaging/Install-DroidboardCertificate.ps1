param(
    [string]$CertificatePath = (Join-Path $PSScriptRoot "MySoftware-CodeSigning.cer")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
    throw "Certificate not found: $CertificatePath"
}

$ResolvedCertificate = (Resolve-Path -LiteralPath $CertificatePath).Path
$Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ResolvedCertificate)

Write-Host "Droidboard certificate to trust:" -ForegroundColor Cyan
Write-Host "  Subject:     $($Certificate.Subject)"
Write-Host "  Issuer:      $($Certificate.Issuer)"
Write-Host "  Thumbprint:  $($Certificate.Thumbprint)"
Write-Host "  Expires:     $($Certificate.NotAfter)"
Write-Warning "Continue only if the thumbprint matches the value supplied by the publisher."
Write-Warning "This action trusts applications signed with this certificate for the current user."

$Confirmation = Read-Host "Type INSTALL to continue"
if ($Confirmation -cne "INSTALL") {
    Write-Host "Operation cancelled."
    exit 1
}

Import-Certificate -FilePath $ResolvedCertificate -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null
Import-Certificate -FilePath $ResolvedCertificate -CertStoreLocation "Cert:\CurrentUser\TrustedPublisher" | Out-Null

$Thumbprint = $Certificate.Thumbprint
if (-not (Test-Path "Cert:\CurrentUser\Root\$Thumbprint") -or
    -not (Test-Path "Cert:\CurrentUser\TrustedPublisher\$Thumbprint")) {
    throw "Certificate installation failed."
}

Write-Host "The certificate was installed successfully for the current user." -ForegroundColor Green
