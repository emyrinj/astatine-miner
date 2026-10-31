param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$CommitSha
)

$ErrorActionPreference = 'Stop'
$Version = '0.1.0-testnet.13'
$Repository = 'emyrinj/astatine-miner'
$Temp = Join-Path $env:TEMP ("astatine-public-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
    $Installer = Join-Path $Temp 'install-windows.ps1'
    $InstallerUrl = "https://raw.githubusercontent.com/$Repository/$CommitSha/support/install-windows.ps1"
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $Installer -TimeoutSec 60
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Installer
    if ($LASTEXITCODE -ne 0) { throw 'Public Windows installer returned a failure exit code' }

    $InstallDir = Join-Path $HOME 'bin'
    $InstalledExe = Join-Path $InstallDir 'astatine.exe'
    if (-not (Test-Path -LiteralPath $InstalledExe)) { throw 'Public installer did not install astatine.exe' }
    $VersionOutput = & $InstalledExe --version
    $VersionLines = @($VersionOutput)
    if ($LASTEXITCODE -ne 0 -or $VersionLines.Count -ne 1 -or $VersionLines[0] -cne "astatine $Version") {
        throw 'Publicly installed executable has the wrong version'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'licenses\LICENSE-MIT'))) {
        throw 'Public installer did not install the MIT notice'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'licenses\THIRD_PARTY_LICENSES.md'))) {
        throw 'Public installer did not install third-party notices'
    }
} finally {
    Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
