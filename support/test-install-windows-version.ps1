$ErrorActionPreference = 'Stop'

$Installer = Join-Path $PSScriptRoot 'install-windows.ps1'
$Updater = Join-Path $PSScriptRoot 'update-windows.ps1'
$PowerShellCommand = Get-Command powershell.exe -ErrorAction SilentlyContinue
if ($null -eq $PowerShellCommand) {
    $PowerShellCommand = Get-Command pwsh -ErrorAction SilentlyContinue
}
if ($null -eq $PowerShellCommand) {
    throw 'Windows PowerShell or PowerShell 7 is required for the installer version tests.'
}
$PowerShellPath = $PowerShellCommand.Source

function Invoke-AstatineVersionComparison([string]$ScriptPath, [string]$Current, [string]$Candidate) {
    $StartInfo = [System.Diagnostics.ProcessStartInfo]::new($script:PowerShellPath)
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    foreach ($Argument in @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $ScriptPath,
        '-CompareVersions',
        '-CurrentVersion',
        $Current,
        '-CandidateVersion',
        $Candidate
    )) {
        $StartInfo.ArgumentList.Add($Argument)
    }

    $Process = [System.Diagnostics.Process]::Start($StartInfo)
    $StandardOutput = $Process.StandardOutput.ReadToEnd()
    $StandardError = $Process.StandardError.ReadToEnd()
    $Process.WaitForExit()
    [pscustomobject]@{
        ExitCode = $Process.ExitCode
        Output = $StandardOutput.Trim()
        Error = $StandardError.Trim()
    }
}

function Invoke-AstatineVersionOutputCheck([string]$ScriptPath, [string]$Expected, [string[]]$Lines) {
    $StartInfo = [System.Diagnostics.ProcessStartInfo]::new($script:PowerShellPath)
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $OutputJson = ConvertTo-Json -InputObject @($Lines) -Compress
    foreach ($Argument in @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $ScriptPath,
        '-VerifyVersionOutput',
        '-ExpectedVersion',
        $Expected,
        '-VersionOutputJson',
        $OutputJson
    )) {
        $StartInfo.ArgumentList.Add($Argument)
    }

    $Process = [System.Diagnostics.Process]::Start($StartInfo)
    $StandardOutput = $Process.StandardOutput.ReadToEnd()
    $StandardError = $Process.StandardError.ReadToEnd()
    $Process.WaitForExit()
    [pscustomobject]@{
        ExitCode = $Process.ExitCode
        Output = $StandardOutput.Trim()
        Error = $StandardError.Trim()
    }
}

# Exercise expected nonzero child exits while the outer shell uses strict native
# command handling. The process API keeps those exit codes available for tests.
$PreviousNativeCommandPreference = $PSNativeCommandUseErrorActionPreference
$PSNativeCommandUseErrorActionPreference = $true
try {
    $ValidCases = @(
        @{ Current = 'astatine 0.1.0-testnet.12'; Candidate = '0.1.0-testnet.13'; Expected = '-1' },
        @{ Current = '0.1.0-testnet.13'; Candidate = '0.1.0-testnet.13'; Expected = '0' },
        @{ Current = '0.1.0-testnet.14'; Candidate = '0.1.0-testnet.13'; Expected = '1' },
        @{ Current = '0.1.0-testnet.0'; Candidate = '0.1.0-testnet.1'; Expected = '-1' },
        @{ Current = '0.1.0-testnet.2147483647'; Candidate = '0.1.0-testnet.2147483646'; Expected = '1' },
        @{ Current = '0.1.0-testnet.99'; Candidate = '0.1.0'; Expected = '-1' },
        @{ Current = '0.1.0'; Candidate = '0.1.0-testnet.99'; Expected = '1' },
        @{ Current = '0.1.1-testnet.1'; Candidate = '0.1.0-testnet.99'; Expected = '1' },
        @{ Current = '0.1.1'; Candidate = '0.1.0'; Expected = '1' },
        @{ Current = '0.1.1-testnet.1'; Candidate = '0.1.2-testnet.0'; Expected = '-1' },
        @{ Current = '0.1.0'; Candidate = '0.2.0'; Expected = '-1' },
        @{ Current = '1.0.0'; Candidate = '0.99.99'; Expected = '1' },
        @{ Current = '2147483646.0.0'; Candidate = '2147483647.0.0'; Expected = '-1' }
    )
    $InvalidVersions = @(
        'not-a-version',
        '0.1',
        'v0.1.0',
        '0.1.0-preview.1',
        '0.1.0-testnet.foo',
        '00.1.0',
        '0.01.0',
        '0.1.00',
        '0.1.0-testnet.013',
        '2147483648.0.0',
        '0.1.0-testnet.2147483648',
        '18446744073709551616.0.0'
    )

    foreach ($Script in @($Installer, $Updater)) {
        $ScriptName = Split-Path -Leaf $Script
        foreach ($Case in $ValidCases) {
            $Result = Invoke-AstatineVersionComparison $Script $Case.Current $Case.Candidate
            if ($Result.ExitCode -ne 0 -or $Result.Output -ne $Case.Expected) {
                throw "$ScriptName comparison failed: $($Case.Current) vs $($Case.Candidate); expected $($Case.Expected), got exit=$($Result.ExitCode) output='$($Result.Output)' error='$($Result.Error)'"
            }
        }
        foreach ($Invalid in $InvalidVersions) {
            foreach ($Position in @('current', 'candidate')) {
                $Current = if ($Position -eq 'current') { $Invalid } else { '0.1.0-testnet.12' }
                $Candidate = if ($Position -eq 'candidate') { $Invalid } else { '0.1.0-testnet.13' }
                $Result = Invoke-AstatineVersionComparison $Script $Current $Candidate
                if ($Result.ExitCode -ne 2 -or [string]::IsNullOrWhiteSpace($Result.Error)) {
                    throw "$ScriptName accepted invalid $Position version '$Invalid'; exit=$($Result.ExitCode) output='$($Result.Output)' error='$($Result.Error)'"
                }
            }
        }

        $ExpectedVersionOutput = Invoke-AstatineVersionOutputCheck `
            $Script '0.1.0-testnet.13' @('astatine 0.1.0-testnet.13')
        if ($ExpectedVersionOutput.ExitCode -ne 0 -or $ExpectedVersionOutput.Output -ne '0') {
            throw "${ScriptName} rejected its exact version output: $($ExpectedVersionOutput | ConvertTo-Json -Compress)"
        }
        foreach ($InvalidOutput in @(
            @('astatine 0.1.0-testnet.130'),
            @('astatine 0.1.0-testnet.foo'),
            @('astatine 0.1.0-testnet.12'),
            @('astatine 0.1.0-testnet.13 '),
            @('0.1.0-testnet.13'),
            @(' astatine 0.1.0-testnet.13'),
            @('malformed version output'),
            @('astatine 0.1.0-testnet.13', 'extra output line'),
            @('astatine 0.1.0-testnet.13', '')
        )) {
            $RejectedOutput = Invoke-AstatineVersionOutputCheck `
                $Script '0.1.0-testnet.13' $InvalidOutput
            if ($RejectedOutput.ExitCode -ne 2 -or [string]::IsNullOrWhiteSpace($RejectedOutput.Error)) {
                throw "${ScriptName} accepted malformed executable version output $($InvalidOutput -join '|'): $($RejectedOutput | ConvertTo-Json -Compress)"
            }
        }
    }
} finally {
    $PSNativeCommandUseErrorActionPreference = $PreviousNativeCommandPreference
}

Write-Output 'Windows bootstrap and updater SemVer ordering/fail-closed tests passed.'
