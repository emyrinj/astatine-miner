param(
    [Parameter(Mandatory = $true)][string]$PackageDirectory,
    [Parameter(Mandatory = $true)][string]$ReleaseTag,
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$TemporaryDirectory
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$Package = $PackageDirectory
$Archive = Join-Path $Package 'astatine-windows-x86_64.zip'
$ManifestPath = Join-Path $Package 'update-manifest.txt'
if ((Get-Item -LiteralPath $ManifestPath).Length -gt 2097152) { throw 'Unsigned manifest exceeds its size limit' }
$ManifestLines = Get-Content -LiteralPath $ManifestPath
if ($ManifestLines[0] -ne 'astatine-update-manifest-v1') { throw 'Unsigned manifest format is invalid' }
if ($ManifestLines -notcontains "version=$($ReleaseTag.Substring(1))") { throw 'Manifest version does not match the release tag' }
if ($ManifestLines -notcontains "repository=$Repository") { throw 'Manifest repository identity is invalid' }
if ($ManifestLines -notcontains 'channel=testnet') { throw 'Manifest channel is not Testnet' }

$PackageLines = @($ManifestLines | Where-Object { $_.StartsWith('asset.package.windows-x86_64=') })
if ($PackageLines.Count -ne 1) { throw 'Unsigned manifest must contain exactly one Windows package record' }
$PackageRecord = $PackageLines[0].Substring($PackageLines[0].IndexOf('=') + 1).Split('|')
if ($PackageRecord.Count -ne 3 -or $PackageRecord[0] -ne 'astatine-windows-x86_64.zip') { throw 'Unsigned Windows package record is malformed' }
if ((Get-FileHash -Path $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $PackageRecord[1]) { throw 'Windows package hash does not match unsigned manifest' }
if ((Get-Item -LiteralPath $Archive).Length -ne [Int64]$PackageRecord[2]) { throw 'Windows package size does not match unsigned manifest' }

$BinaryPath = Join-Path $Package 'astatine-windows-x86_64.exe'
$BinaryLines = @($ManifestLines | Where-Object { $_.StartsWith('asset.binary.windows-x86_64=') })
if ($BinaryLines.Count -ne 1) { throw 'Unsigned manifest must contain exactly one Windows binary record' }
$BinaryRecord = $BinaryLines[0].Substring($BinaryLines[0].IndexOf('=') + 1).Split('|')
if ($BinaryRecord.Count -ne 3 -or $BinaryRecord[0] -ne 'astatine-windows-x86_64.exe') { throw 'Unsigned Windows binary record is malformed' }
if ((Get-FileHash -Path $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $BinaryRecord[1]) { throw 'Windows binary hash does not match unsigned manifest' }
if ((Get-Item -LiteralPath $BinaryPath).Length -ne [Int64]$BinaryRecord[2]) { throw 'Windows binary size does not match unsigned manifest' }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$Zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
try {
    $ZipNames = @($Zip.Entries | ForEach-Object { $_.FullName })
    $ExpectedNames = @('astatine.exe', 'LICENSE-MIT', 'THIRD_PARTY_LICENSES.md')
    if ($ZipNames.Count -ne 3 -or (Compare-Object ($ZipNames | Sort-Object) ($ExpectedNames | Sort-Object))) {
        throw 'Windows ZIP member allowlist mismatch'
    }
} finally {
    $Zip.Dispose()
}

$ExtractDir = Join-Path $TemporaryDirectory 'astatine-windows-extracted'
$InstallDir = Join-Path $TemporaryDirectory 'astatine-windows-install\bin'
Expand-Archive -Path $Archive -DestinationPath $ExtractDir
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $InstallDir 'licenses') -Force | Out-Null
Copy-Item (Join-Path $ExtractDir 'astatine.exe') (Join-Path $InstallDir 'astatine.exe')
Copy-Item (Join-Path $ExtractDir 'LICENSE-MIT') (Join-Path $InstallDir 'licenses\LICENSE-MIT')
Copy-Item (Join-Path $ExtractDir 'THIRD_PARTY_LICENSES.md') (Join-Path $InstallDir 'licenses\THIRD_PARTY_LICENSES.md')
$InstalledExecutable = Join-Path $InstallDir 'astatine.exe'
function Invoke-PackagedExecutableSmoke([string[]]$ExecutableArguments) {
    Write-Host "Smoke testing unsigned packaged Windows executable: $($ExecutableArguments -join ' ')"
    $ExecutableOutput = & $InstalledExecutable @ExecutableArguments 2>&1
    $ExecutableExitCode = $LASTEXITCODE
    if ($ExecutableExitCode -ne 0) {
        $ExecutableOutput | ForEach-Object { Write-Host $_ }
        throw "Packaged Windows executable failed '$($ExecutableArguments -join ' ')': exit code $ExecutableExitCode"
    }
}
Invoke-PackagedExecutableSmoke -ExecutableArguments @('--version')
Invoke-PackagedExecutableSmoke -ExecutableArguments @('--help')
Invoke-PackagedExecutableSmoke -ExecutableArguments @('mine', '--help')

# The updater helper only applies already-verified staged files; signature and
# provenance validation happen before this release package is staged.
$HelperRoot = Join-Path $TemporaryDirectory 'astatine-update-helper-smoke'
$HelperLicenses = Join-Path $HelperRoot 'licenses'
$HelperExe = Join-Path $HelperRoot 'astatine.exe'
New-Item -ItemType Directory -Path $HelperRoot -Force | Out-Null
New-Item -ItemType Directory -Path $HelperLicenses -Force | Out-Null
Copy-Item (Join-Path $ExtractDir 'astatine.exe') $HelperExe
Set-Content -LiteralPath (Join-Path $HelperLicenses 'LICENSE-MIT') 'old MIT notice'
Set-Content -LiteralPath (Join-Path $HelperLicenses 'THIRD_PARTY_LICENSES.md') 'old dependency notices'
$HelperPlan = Join-Path $HelperRoot 'plan.json'
$HelperLog = Join-Path $HelperRoot 'update.log'
$HelperLock = Join-Path $HelperRoot '.astatine-update.lock'
$DummyParent = Start-Process -FilePath $env:ComSpec -ArgumentList '/c', 'ping -n 3 127.0.0.1 > nul' -PassThru -WindowStyle Hidden

function Write-HelperPlan([string]$ExpectedVersion) {
    $Files = @(
        @{ destination = $HelperExe; staged = "$HelperExe.update"; backup = "$HelperExe.backup" },
        @{ destination = (Join-Path $HelperLicenses 'LICENSE-MIT'); staged = (Join-Path $HelperLicenses 'LICENSE-MIT.update'); backup = (Join-Path $HelperLicenses 'LICENSE-MIT.backup') },
        @{ destination = (Join-Path $HelperLicenses 'THIRD_PARTY_LICENSES.md'); staged = (Join-Path $HelperLicenses 'THIRD_PARTY_LICENSES.md.update'); backup = (Join-Path $HelperLicenses 'THIRD_PARTY_LICENSES.md.backup') }
    )
    @{ expected_version = $ExpectedVersion; executable = $HelperExe; lock = $HelperLock; log = $HelperLog; files = $Files } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $HelperPlan -Encoding UTF8
}

Copy-Item $BinaryPath "$HelperExe.update"
Copy-Item (Join-Path $ExtractDir 'LICENSE-MIT') (Join-Path $HelperLicenses 'LICENSE-MIT.update')
Copy-Item (Join-Path $ExtractDir 'THIRD_PARTY_LICENSES.md') (Join-Path $HelperLicenses 'THIRD_PARTY_LICENSES.md.update')
Write-HelperPlan $ReleaseTag.Substring(1)
$HelperOutput = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'update-windows.ps1') -ParentPid $DummyParent.Id -PlanPath $HelperPlan 2>&1
$HelperExitCode = $LASTEXITCODE
$HelperOutput | ForEach-Object { Write-Host $_ }
if ($HelperExitCode -ne 0) {
    if (Test-Path -LiteralPath $HelperLog) { Get-Content -LiteralPath $HelperLog }
    throw "Windows update helper failed its install case (exit code $HelperExitCode)"
}
if ((Get-Content (Join-Path $HelperLicenses 'LICENSE-MIT') -Raw) -ne (Get-Content (Join-Path $ExtractDir 'LICENSE-MIT') -Raw)) { throw 'Windows update helper did not install license notices' }

$OldExecutableHash = (Get-FileHash -Path $HelperExe -Algorithm SHA256).Hash
Set-Content -LiteralPath (Join-Path $HelperLicenses 'LICENSE-MIT') 'preserve this on rollback'
Copy-Item $BinaryPath "$HelperExe.update"
Copy-Item (Join-Path $ExtractDir 'LICENSE-MIT') (Join-Path $HelperLicenses 'LICENSE-MIT.update')
Copy-Item (Join-Path $ExtractDir 'THIRD_PARTY_LICENSES.md') (Join-Path $HelperLicenses 'THIRD_PARTY_LICENSES.md.update')
Write-HelperPlan '0.1.0-testnet.2147483647'
$HelperOutput = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'update-windows.ps1') -ParentPid $DummyParent.Id -PlanPath $HelperPlan 2>&1
$HelperExitCode = $LASTEXITCODE
$HelperOutput | ForEach-Object { Write-Host $_ }
if ($HelperExitCode -eq 0) {
    if (Test-Path -LiteralPath $HelperLog) { Get-Content -LiteralPath $HelperLog }
    throw 'Windows update helper unexpectedly accepted a mismatched smoke-test version'
}
if ((Get-FileHash -Path $HelperExe -Algorithm SHA256).Hash -ne $OldExecutableHash) { throw 'Windows update helper failed to restore the previous executable' }
if ((Get-Content (Join-Path $HelperLicenses 'LICENSE-MIT') -Raw).Trim() -ne 'preserve this on rollback') { throw 'Windows update helper failed to restore the previous license notice' }
$global:LASTEXITCODE = 0
