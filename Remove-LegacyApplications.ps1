#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Validates and uninstalls selected legacy applications.
.DESCRIPTION
    Reads 64-bit and 32-bit HKLM uninstall registry keys, validates approved
    application names and publishers, displays the proposed actions, and
    requires the operator to type exactly YES before making changes.

    MSI packages are removed by ProductCode. Other applications are removed
    only when a parseable QuietUninstallString is available. Unsupported
    uninstall methods are marked as MANUAL DEINSTALLATION REQUIRED.

    The script does not restart the server automatically.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# Configuration
# ============================================================
$TimeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogDirectory = 'C:\Temp'
$TranscriptPath = Join-Path -Path $LogDirectory -ChildPath "LegacyApplicationRemoval-$TimeStamp.log"
$CsvPath = Join-Path -Path $LogDirectory -ChildPath "LegacyApplicationRemoval-$TimeStamp.csv"

if (-not (Test-Path -LiteralPath $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}

# ============================================================
# Applications approved for removal
# ============================================================
$TargetApplications = @(
    [pscustomobject]@{
        TargetName       = 'ASE'
        NamePattern      = '^ASE$'
        PublisherPattern = '^Atos$'
    }
    [pscustomobject]@{
        TargetName       = 'Compliance Scanner'
        NamePattern      = '^Compliance Scanner(?: Version)?(?:\s+.*)?$'
        PublisherPattern = '^Atos$'
    }
    [pscustomobject]@{
        TargetName       = 'ItrionAgent'
        NamePattern      = '^ItrionAgent(?: Version)?(?:\s+.*)?$'
        PublisherPattern = '^Atos$'
    }
    [pscustomobject]@{
        TargetName       = 'Atos CMF Client NaCl'
        NamePattern      = "^Atos CMF Client\s+'?NaCl'?$"
        PublisherPattern = '^Atos SE$'
    }
    [pscustomobject]@{
        TargetName       = 'Citrix VM Tools'
        NamePattern      = '^Citrix VM Tools(?:\s+.*)?$'
        PublisherPattern = '^Citrix.*$'
    }
    [pscustomobject]@{
        TargetName       = 'Veeam Agent for Microsoft Windows'
        NamePattern      = '^Veeam Agent for Microsoft Windows(?:\s+.*)?$'
        PublisherPattern = '^Veeam.*$'
    }
    [pscustomobject]@{
        TargetName       = 'TrueSight Server Automation RSCD Agent'
        NamePattern      = '^TrueSight Server Automation RSCD Agent(?:\s+.*)?$'
        PublisherPattern = '^BMC Software.*$'
    }
)

# ============================================================
# Registry locations
# ============================================================
$RegistryLocations = @(
    [pscustomobject]@{
        Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        Architecture = '64-bit'
    }
    [pscustomobject]@{
        Path         = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        Architecture = '32-bit'
    }
)

# ============================================================
# FUNCTION: Safely read a property from a registry object
# ============================================================
function Get-ObjectPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    $Property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $Property -or $null -eq $Property.Value) {
        return $null
    }

    return $Property.Value
}

# ============================================================
# FUNCTION: Get installed applications
# ============================================================
function Get-InstalledApplications {
    [CmdletBinding()]
    param()

    $Applications = [System.Collections.Generic.List[object]]::new()

    foreach ($RegistryLocation in $RegistryLocations) {
        $RegistryApplications = @(
            Get-ItemProperty -Path $RegistryLocation.Path -ErrorAction SilentlyContinue
        )

        foreach ($RegistryApplication in $RegistryApplications) {
            $DisplayName = [string](Get-ObjectPropertyValue -InputObject $RegistryApplication -PropertyName 'DisplayName')

            if ([string]::IsNullOrWhiteSpace($DisplayName)) {
                continue
            }

            $Applications.Add(
                [pscustomobject]@{
                    DisplayName          = $DisplayName.Trim()
                    DisplayVersion       = [string](Get-ObjectPropertyValue -InputObject $RegistryApplication -PropertyName 'DisplayVersion')
                    Publisher            = [string](Get-ObjectPropertyValue -InputObject $RegistryApplication -PropertyName 'Publisher')
                    Architecture         = $RegistryLocation.Architecture
                    QuietUninstallString = [string](Get-ObjectPropertyValue -InputObject $RegistryApplication -PropertyName 'QuietUninstallString')
                    UninstallString      = [string](Get-ObjectPropertyValue -InputObject $RegistryApplication -PropertyName 'UninstallString')
                    WindowsInstaller     = Get-ObjectPropertyValue -InputObject $RegistryApplication -PropertyName 'WindowsInstaller'
                    RegistryKeyName      = [string](Get-ObjectPropertyValue -InputObject $RegistryApplication -PropertyName 'PSChildName')
                    RegistryPath         = [string](Get-ObjectPropertyValue -InputObject $RegistryApplication -PropertyName 'PSPath')
                }
            )
        }
    }

    return $Applications.ToArray()
}

# ============================================================
# FUNCTION: Split an executable command line
# ============================================================
function Split-UninstallCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandLine
    )

    $CommandLine = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())

    if ($CommandLine -match '^"([^\"]+\.exe)"\s*(.*)$') {
        return [pscustomobject]@{
            FilePath  = $Matches[1]
            Arguments = $Matches[2].Trim()
        }
    }

    if ($CommandLine -match '^(\S+\.exe)\s*(.*)$') {
        return [pscustomobject]@{
            FilePath  = $Matches[1]
            Arguments = $Matches[2].Trim()
        }
    }

    return $null
}

# ============================================================
# FUNCTION: Determine a safe uninstall method
# ============================================================
function Get-UninstallPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Application
    )

    $ProductCode = $null
    $IsMsi = $false

    if ($Application.WindowsInstaller -eq 1) {
        $IsMsi = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($Application.UninstallString) -and
        $Application.UninstallString -match '(?i)\bmsiexec(?:\.exe)?\b') {
        $IsMsi = $true
    }

    if ($Application.RegistryKeyName -match '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') {
        $ProductCode = $Application.RegistryKeyName
    }
    elseif (-not [string]::IsNullOrWhiteSpace($Application.UninstallString) -and
            $Application.UninstallString -match '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}') {
        $ProductCode = $Matches[0]
    }

    if ($IsMsi -and -not [string]::IsNullOrWhiteSpace($ProductCode)) {
        return [pscustomobject]@{
            Safe      = $true
            FilePath  = 'msiexec.exe'
            Arguments = "/x $ProductCode /qn /norestart"
            Method    = 'MSI ProductCode'
            Command   = "msiexec.exe /x $ProductCode /qn /norestart"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Application.QuietUninstallString)) {
        $ParsedCommand = Split-UninstallCommand -CommandLine $Application.QuietUninstallString

        if ($null -ne $ParsedCommand) {
            return [pscustomobject]@{
                Safe      = $true
                FilePath  = $ParsedCommand.FilePath
                Arguments = $ParsedCommand.Arguments
                Method    = 'QuietUninstallString'
                Command   = $Application.QuietUninstallString
            }
        }
    }

    return [pscustomobject]@{
        Safe      = $false
        FilePath  = ''
        Arguments = ''
        Method    = 'Manual'
        Command   = $Application.UninstallString
    }
}

# ============================================================
# FUNCTION: Export current results
# ============================================================
function Export-RemovalResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$Results,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $Results.ToArray() |
        Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force
}

# ============================================================
# Main execution
# ============================================================
$TranscriptStarted = $false

try {
    Start-Transcript -Path $TranscriptPath -Force | Out-Null
    $TranscriptStarted = $true

    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' APPLICATION REMOVAL - VALIDATION'
    Write-Host '============================================================'
    Write-Host ''
    Write-Host "Computer : $env:COMPUTERNAME"
    Write-Host "Date     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ''
    Write-Host 'No changes are made during this phase.'
    Write-Host ''

    $InstalledApplications = @(Get-InstalledApplications)
    $ReadyForRemoval = [System.Collections.Generic.List[object]]::new()
    $Results = [System.Collections.Generic.List[object]]::new()

    foreach ($Target in $TargetApplications) {
        $MatchedApplications = @(
            $InstalledApplications | Where-Object {
                $_.DisplayName -match $Target.NamePattern -and
                $_.Publisher -match $Target.PublisherPattern
            }
        )

        if ($MatchedApplications.Count -eq 0) {
            Write-Host "[NOT FOUND] $($Target.TargetName)" -ForegroundColor DarkGray

            $Results.Add(
                [pscustomobject]@{
                    TargetName     = $Target.TargetName
                    Application    = $Target.TargetName
                    Version        = ''
                    Publisher      = ''
                    Architecture   = ''
                    Method         = ''
                    InitialStatus  = 'NOT FOUND'
                    FinalStatus    = 'NOT FOUND'
                    ExitCode       = ''
                    RebootRequired = $false
                }
            )
            continue
        }

        foreach ($Application in $MatchedApplications) {
            $Plan = Get-UninstallPlan -Application $Application

            Write-Host ''
            Write-Host "[FOUND] $($Application.DisplayName)" -ForegroundColor Cyan
            Write-Host "        Publisher : $($Application.Publisher)"
            Write-Host "        Version   : $($Application.DisplayVersion)"
            Write-Host "        Platform  : $($Application.Architecture)"
            Write-Host '        Validation: PASSED' -ForegroundColor Green

            if ($Plan.Safe) {
                Write-Host "        Method    : $($Plan.Method)"
                Write-Host "        Command   : $($Plan.Command)"
                Write-Host '        Status    : READY FOR REMOVAL' -ForegroundColor Green
                $InitialStatus = 'READY FOR REMOVAL'
            }
            else {
                Write-Host "        Uninstall : $($Application.UninstallString)"
                Write-Host '        Status    : MANUAL DEINSTALLATION REQUIRED' -ForegroundColor Red
                $InitialStatus = 'MANUAL DEINSTALLATION REQUIRED'
            }

            $Result = [pscustomobject]@{
                TargetName     = $Target.TargetName
                Application    = $Application.DisplayName
                Version        = $Application.DisplayVersion
                Publisher      = $Application.Publisher
                Architecture   = $Application.Architecture
                Method         = $Plan.Method
                InitialStatus  = $InitialStatus
                FinalStatus    = $InitialStatus
                ExitCode       = ''
                RebootRequired = $false
            }

            $Results.Add($Result)

            if ($Plan.Safe) {
                $ReadyForRemoval.Add(
                    [pscustomobject]@{
                        Application = $Application
                        Plan        = $Plan
                        Result      = $Result
                    }
                )
            }
        }
    }

    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' VALIDATION SUMMARY'
    Write-Host '============================================================'
    Write-Host ''

    $Results.ToArray() |
        Format-Table Application, Version, Publisher, Architecture, InitialStatus -AutoSize -Wrap

    Write-Host ''
    Write-Host "Ready for automatic removal: $($ReadyForRemoval.Count)"

    if ($ReadyForRemoval.Count -eq 0) {
        Write-Host ''
        Write-Host 'Nothing can be removed automatically.' -ForegroundColor Yellow
        Write-Host 'No changes have been made.'
        Export-RemovalResults -Results $Results -Path $CsvPath
        return
    }

    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' APPLICATIONS SELECTED FOR REMOVAL'
    Write-Host '============================================================'
    Write-Host ''

    foreach ($Item in $ReadyForRemoval) {
        Write-Host "$($Item.Application.DisplayName) | $($Item.Application.DisplayVersion) | $($Item.Application.Publisher)"
    }

    Write-Host ''
    Write-Host 'WARNING: Applications listed above will be uninstalled.' -ForegroundColor Red
    Write-Host ''
    Write-Host 'Type exactly YES to continue.' -ForegroundColor Yellow
    Write-Host 'Any other response will cancel the operation.'
    Write-Host ''

    $Confirmation = Read-Host 'Continue'

    if ($Confirmation -cne 'YES') {
        foreach ($Item in $ReadyForRemoval) {
            $Item.Result.FinalStatus = 'CANCELLED BY OPERATOR'
        }

        Write-Host ''
        Write-Host '============================================================'
        Write-Host ' OPERATION CANCELLED'
        Write-Host '============================================================'
        Write-Host ''
        Write-Host 'No applications have been removed.' -ForegroundColor Green

        Export-RemovalResults -Results $Results -Path $CsvPath
        return
    }

    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' UNINSTALLATION STARTED'
    Write-Host '============================================================'
    Write-Host ''

    foreach ($Item in $ReadyForRemoval) {
        $Application = $Item.Application
        $Plan = $Item.Plan
        $Result = $Item.Result

        Write-Host ''
        Write-Host "Removing: $($Application.DisplayName)" -ForegroundColor Yellow
        Write-Host "Version : $($Application.DisplayVersion)"
        Write-Host "Command : $($Plan.Command)"

        try {
            $ProcessParameters = @{
                FilePath    = $Plan.FilePath
                Wait        = $true
                PassThru    = $true
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($Plan.Arguments)) {
                $ProcessParameters.ArgumentList = $Plan.Arguments
            }

            $Process = Start-Process @ProcessParameters
            $ExitCode = [int]$Process.ExitCode
            $Result.ExitCode = $ExitCode

            Write-Host "Exit code: $ExitCode"

            switch ($ExitCode) {
                0 {
                    $Result.FinalStatus = 'UNINSTALLER COMPLETED'
                    Write-Host '[SUCCESS] Uninstaller completed.' -ForegroundColor Green
                }
                1641 {
                    $Result.FinalStatus = 'UNINSTALLER COMPLETED - REBOOT INITIATED/REQUIRED'
                    $Result.RebootRequired = $true
                    Write-Host '[SUCCESS] Uninstaller completed. Reboot is required.' -ForegroundColor Yellow
                }
                3010 {
                    $Result.FinalStatus = 'UNINSTALLER COMPLETED - REBOOT REQUIRED'
                    $Result.RebootRequired = $true
                    Write-Host '[SUCCESS] Uninstaller completed. Reboot is required.' -ForegroundColor Yellow
                }
                default {
                    $Result.FinalStatus = "UNINSTALLER EXIT CODE $ExitCode"
                    Write-Host "[WARNING] Uninstaller returned exit code $ExitCode" -ForegroundColor Yellow
                }
            }
        }
        catch {
            $Result.FinalStatus = "ERROR: $($_.Exception.Message)"
            Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' POST-REMOVAL VALIDATION'
    Write-Host '============================================================'
    Write-Host ''

    $ApplicationsAfterRemoval = @(Get-InstalledApplications)

    foreach ($Item in $ReadyForRemoval) {
        $Application = $Item.Application
        $Result = $Item.Result

        $StillInstalled = @(
            $ApplicationsAfterRemoval | Where-Object {
                $_.DisplayName -eq $Application.DisplayName -and
                $_.Publisher -eq $Application.Publisher -and
                $_.Architecture -eq $Application.Architecture
            }
        )

        if ($StillInstalled.Count -eq 0) {
            $Result.FinalStatus = if ($Result.RebootRequired) {
                'REMOVED - REBOOT REQUIRED'
            }
            else {
                'REMOVED'
            }

            Write-Host "[REMOVED] $($Application.DisplayName) $($Application.DisplayVersion)" -ForegroundColor Green
        }
        else {
            if ($Result.FinalStatus -notlike 'ERROR:*') {
                $Result.FinalStatus = 'STILL INSTALLED'
            }

            Write-Host "[STILL INSTALLED] $($Application.DisplayName) $($Application.DisplayVersion)" -ForegroundColor Red
        }
    }

    Export-RemovalResults -Results $Results -Path $CsvPath

    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' COMPLETED'
    Write-Host '============================================================'
    Write-Host ''
    Write-Host "CSV report : $CsvPath"
    Write-Host "Log        : $TranscriptPath"
    Write-Host ''
    Write-Host 'The script did NOT restart the server.' -ForegroundColor Green
    Write-Host 'Exit code 1641 or 3010 indicates that a reboot may be required.' -ForegroundColor Yellow
}
catch {
    Write-Host ''
    Write-Host "[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Script line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red

    if ($null -ne (Get-Variable -Name Results -ErrorAction SilentlyContinue)) {
        try {
            Export-RemovalResults -Results $Results -Path $CsvPath
        }
        catch {
            Write-Host "[WARNING] CSV export failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    throw
}
finally {
    if ($TranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            # Ignore transcript cleanup errors.
        }
    }
}
