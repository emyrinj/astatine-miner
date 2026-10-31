param(
    [switch]$CompareVersions,
    [string]$CurrentVersion,
    [string]$CandidateVersion,
    [switch]$VerifyVersionOutput,
    [string]$ExpectedVersion,
    [string]$VersionOutputJson
)

$ErrorActionPreference = 'Stop'

function ConvertTo-AstatineVersion([string]$Text) {
    $Match = [regex]::Match(
        $Text,
        '^(?:astatine\s+)?(?<Major>0|[1-9][0-9]*)\.(?<Minor>0|[1-9][0-9]*)\.(?<Patch>0|[1-9][0-9]*)(?:-testnet\.(?<Sequence>0|[1-9][0-9]*))?$'
    )
    if (-not $Match.Success) { throw "Unsupported Astatine version format: $Text" }
    $Values = @(
        [System.UInt64]::Parse($Match.Groups['Major'].Value, [System.Globalization.CultureInfo]::InvariantCulture),
        [System.UInt64]::Parse($Match.Groups['Minor'].Value, [System.Globalization.CultureInfo]::InvariantCulture),
        [System.UInt64]::Parse($Match.Groups['Patch'].Value, [System.Globalization.CultureInfo]::InvariantCulture)
    )
    if ($Values | Where-Object { $_ -gt 2147483647 }) { throw "Astatine version component exceeds the supported SemVer range: $Text" }
    $IsPrerelease = $Match.Groups['Sequence'].Success
    $Sequence = [UInt64]0
    if ($IsPrerelease) {
        $Sequence = [System.UInt64]::Parse($Match.Groups['Sequence'].Value, [System.Globalization.CultureInfo]::InvariantCulture)
        if ($Sequence -gt 2147483647) { throw "Astatine prerelease identifier exceeds the supported SemVer range: $Text" }
    }
    return [pscustomobject]@{
        Major = $Values[0]
        Minor = $Values[1]
        Patch = $Values[2]
        IsPrerelease = $IsPrerelease
        Sequence = $Sequence
    }
}

function Compare-AstatineVersions([string]$Current, [string]$Candidate) {
    $CurrentParsed = ConvertTo-AstatineVersion $Current
    $CandidateParsed = ConvertTo-AstatineVersion $Candidate
    foreach ($Field in @('Major', 'Minor', 'Patch')) {
        if ($CurrentParsed.$Field -lt $CandidateParsed.$Field) { return -1 }
        if ($CurrentParsed.$Field -gt $CandidateParsed.$Field) { return 1 }
    }
    if ($CurrentParsed.IsPrerelease -ne $CandidateParsed.IsPrerelease) {
        if ($CurrentParsed.IsPrerelease) { return -1 }
        return 1
    }
    if ($CurrentParsed.IsPrerelease) {
        if ($CurrentParsed.Sequence -lt $CandidateParsed.Sequence) { return -1 }
        if ($CurrentParsed.Sequence -gt $CandidateParsed.Sequence) { return 1 }
    }
    return 0
}

function Assert-AstatineVersionOutput([string[]]$Output, [string]$Expected) {
    if ($null -eq $Output -or $Output.Count -ne 1) {
        throw 'Executable --version output must contain exactly one line'
    }
    $null = ConvertTo-AstatineVersion $Expected
    if ($Output[0] -cne "astatine $Expected") {
        throw 'Executable --version output does not exactly match the expected version'
    }
}

if ($CompareVersions) {
    try {
        if (-not $CurrentVersion -or -not $CandidateVersion) { throw 'Both current and candidate versions are required' }
        Write-Output (Compare-AstatineVersions $CurrentVersion $CandidateVersion)
        exit 0
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 2
    }
}

if ($VerifyVersionOutput) {
    try {
        if (-not $ExpectedVersion) { throw 'ExpectedVersion is required' }
        $OutputLines = @(ConvertFrom-Json -InputObject $VersionOutputJson)
        Assert-AstatineVersionOutput $OutputLines $ExpectedVersion
        Write-Output '0'
        exit 0
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 2
    }
}

$Version = '0.1.0-testnet.13'
$Repository = 'emyrinj/astatine-miner'
$Asset = 'astatine-windows-x86_64.zip'
$Base = "https://github.com/$Repository/releases/download/v$Version"
$Temp = Join-Path $env:TEMP ("astatine-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
    $Manifest = Join-Path $Temp 'update-manifest.txt'
    $Signature = Join-Path $Temp 'update-manifest.sig'
    Invoke-WebRequest -Uri "$Base/update-manifest.txt" -OutFile $Manifest -TimeoutSec 60
    Invoke-WebRequest -Uri "$Base/update-manifest.sig" -OutFile $Signature -TimeoutSec 60
    if ((Get-Item -LiteralPath $Manifest).Length -gt 2097152) { throw 'Release manifest exceeds its size limit' }
    if ((Get-Item -LiteralPath $Signature).Length -ne 384) { throw 'Release signature has an invalid length' }
    $KeyXml = '<RSAKeyValue><Modulus>1Qxetx4KvnfuhGEP17i09JKEg2WYQ5ExtGc8ioSsVi4zsghLCaDL2WKs0ibGyTa2Gju2x0UTGHRuUBHEaDtaAs4oirYtVwwvj5Jca14zc2ggL1ZcwBiN+B3GvTwOot+kd/QBcp+yFiGj2YdUtt9PZcIweIi0LZnbJGyl+khfWQ3iHa+1bpCzin5KLGcPFD2UevErRx/WbKJzg2qdxkGKESDLQc9panAqZTbEkYzKQhrIJBJPBuOGJZc+K+KzeLd+iLNx31UUUaRcUtJ0g3NOgIA8z3EVM6dRnbVmT1Wk5UV5RFNAujfb7ptVx7q3fzxkV7d5Fuk0VFlSU4WddWyNsGHFpZj/U/n3yh0vRzyt08yLVsYRKpKqKFvZSN/Ad4ARYto7POee4Alu6kWHALdqIwWqR9TT5IYyiCze37ZwZcU3Mqq1t6VytWdP9GMHlWVw87v7/BglcSgb+h7e7+YN9ok5BTW/eZYqd5B1/xljaiUUHanhzQ6dX2vPnCwF5jz7</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'
    $Rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $Rsa.FromXmlString($KeyXml)
    $ManifestBytes = [System.IO.File]::ReadAllBytes($Manifest)
    $SignatureBytes = [System.IO.File]::ReadAllBytes($Signature)
    if ($SignatureBytes.Length -ne 384) { throw 'Release signature has an invalid length' }
    $Sha256Oid = [System.Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256')
    if (-not $Rsa.VerifyData($ManifestBytes, $Sha256Oid, $SignatureBytes)) {
        throw 'Release manifest signature verification failed'
    }
    $ManifestLines = Get-Content -LiteralPath $Manifest
    if ($ManifestLines[0] -ne 'astatine-update-manifest-v1') { throw 'Unsupported release manifest format' }
    if ($ManifestLines -notcontains "repository=$Repository") { throw 'Manifest repository identity is invalid' }
    if ($ManifestLines -notcontains 'channel=testnet') { throw 'Manifest channel is not Testnet' }
    $VersionLine = $ManifestLines | Where-Object { $_.StartsWith('version=') }
    if ($VersionLine -ne "version=$Version") { throw 'Signed manifest version does not match this installer' }
    $AssetLine = $ManifestLines | Where-Object { $_.StartsWith('asset.package.windows-x86_64=') }
    if (-not $AssetLine) { throw 'Signed manifest has no Windows package' }
    $Record = $AssetLine.Substring($AssetLine.IndexOf('=') + 1).Split('|')
    if ($Record.Count -ne 3 -or $Record[0] -ne $Asset) { throw 'Signed Windows package record is malformed' }

    $Archive = Join-Path $Temp $Asset
    Invoke-WebRequest -Uri "$Base/$Asset" -OutFile $Archive -TimeoutSec 180
    if ((Get-FileHash -Path $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Record[1]) {
        throw 'Windows package SHA-256 does not match the signed manifest'
    }
    if ((Get-Item -LiteralPath $Archive).Length -ne [Int64]$Record[2]) {
        throw 'Windows package length does not match the signed manifest'
    }

    $Extract = Join-Path $Temp 'extracted'
    Expand-Archive -LiteralPath $Archive -DestinationPath $Extract
    $Entries = @(Get-ChildItem -LiteralPath $Extract -File | ForEach-Object { $_.Name } | Sort-Object)
    $Expected = @('LICENSE-MIT', 'THIRD_PARTY_LICENSES.md', 'astatine.exe') | Sort-Object
    if (($Entries -join '|') -ne ($Expected -join '|')) { throw 'Windows archive contains unexpected files' }
    $StagedExe = Join-Path $Extract 'astatine.exe'
    $VersionOutput = & $StagedExe --version
    if ($LASTEXITCODE -ne 0) {
        throw 'Downloaded executable failed its version smoke test'
    }
    Assert-AstatineVersionOutput $VersionOutput $Version

    $InstallDir = Join-Path $HOME 'bin'
    $ExistingExe = Join-Path $InstallDir 'astatine.exe'
    if (Test-Path -LiteralPath $ExistingExe) {
        $ExistingVersionOutput = & $ExistingExe --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw 'Refusing to replace an existing Astatine executable whose version could not be read'
        }
        $VersionOrder = Compare-AstatineVersions ($ExistingVersionOutput -join "`n") $Version
        if ($VersionOrder -gt 0) {
            throw "Refusing to replace newer Astatine $($ExistingVersionOutput -join ' ') with $Version"
        }
    }
    $LicenseDir = Join-Path $InstallDir 'licenses'
    New-Item -ItemType Directory -Path $LicenseDir -Force | Out-Null
    $Files = @(
        @{ Source = $StagedExe; Destination = (Join-Path $InstallDir 'astatine.exe') },
        @{ Source = (Join-Path $Extract 'LICENSE-MIT'); Destination = (Join-Path $LicenseDir 'LICENSE-MIT') },
        @{ Source = (Join-Path $Extract 'THIRD_PARTY_LICENSES.md'); Destination = (Join-Path $LicenseDir 'THIRD_PARTY_LICENSES.md') }
    )
    $Backups = @()
    try {
        foreach ($File in $Files) {
            $Stage = "$($File.Destination).update"
            $Backup = "$($File.Destination).backup"
            Copy-Item -LiteralPath $File.Source -Destination $Stage -Force
            $HadOriginal = Test-Path -LiteralPath $File.Destination
            if ($HadOriginal) { Move-Item -LiteralPath $File.Destination -Destination $Backup -Force }
            $Backups += @{ Destination = $File.Destination; Backup = $Backup; HadOriginal = $HadOriginal }
            Move-Item -LiteralPath $Stage -Destination $File.Destination -Force
        }
        $InstalledVersion = & (Join-Path $InstallDir 'astatine.exe') --version
        if ($LASTEXITCODE -ne 0) {
            throw 'Installed executable failed its version smoke test'
        }
        Assert-AstatineVersionOutput $InstalledVersion $Version
        foreach ($Backup in $Backups) {
            if ($Backup.HadOriginal) { Remove-Item -LiteralPath $Backup.Backup -Force }
        }
    } catch {
        for ($Index = $Backups.Count - 1; $Index -ge 0; $Index--) {
            $Backup = $Backups[$Index]
            if (Test-Path -LiteralPath $Backup.Destination) { Remove-Item -LiteralPath $Backup.Destination -Force }
            if ($Backup.HadOriginal -and (Test-Path -LiteralPath $Backup.Backup)) {
                Move-Item -LiteralPath $Backup.Backup -Destination $Backup.Destination -Force
            }
        }
        throw
    }
    & (Join-Path $InstallDir 'astatine.exe') --version
    Write-Host "Installed authenticated Astatine $Version in $InstallDir"
} finally {
    Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
