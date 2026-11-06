# Signs SystemForge.exe (inside a publish folder) and the MSI with a code-signing certificate.
# Run on Windows with the Windows SDK installed (signtool.exe). Examples:
#   .\sign.ps1 -Msi .\SystemForge-Setup-0.4.0.msi -Thumbprint <cert thumbprint>          # certificate in your store
#   .\sign.ps1 -Msi .\SystemForge-Setup-0.4.0.msi -PfxPath .\cert.pfx -PfxPassword ***   # certificate file
# Windows SmartScreen only trusts installers signed with a certificate from a public CA (an OV or EV code-signing
# certificate, or Azure Trusted Signing). A self-signed certificate removes nothing.
param(
  [Parameter(Mandatory)] [string] $Msi,
  [string] $Thumbprint,
  [string] $PfxPath,
  [string] $PfxPassword,
  [string] $TimestampUrl = "http://timestamp.digicert.com"
)
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found. Install the Windows SDK (Signing Tools) first." }
$args = @("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $TimestampUrl)
if ($Thumbprint) { $args += @("/sha1", $Thumbprint) } elseif ($PfxPath) { $args += @("/f", $PfxPath); if ($PfxPassword) { $args += @("/p", $PfxPassword) } } else { throw "Give -Thumbprint or -PfxPath." }
& $signtool.FullName @args $Msi
if ($LASTEXITCODE -ne 0) { throw "Signing failed." }
Get-FileHash $Msi -Algorithm SHA256 | ForEach-Object { $_.Hash.ToLower() } | Set-Content "$Msi.sha256" -NoNewline
Write-Host "Signed $Msi and refreshed its .sha256"
