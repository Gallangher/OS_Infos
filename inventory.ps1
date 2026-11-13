<#
.SYNOPSIS
    Windows Server Inventory Report

.DESCRIPTION
    Collects configuration and inventory information from a Windows system
    and generates an HTML report.

    The report includes:

    - Operating system information:
      OS name, architecture, build number, language, installation date,
      time zone, last boot time, uptime and pending reboot status.

    - Hardware information:
      Manufacturer, hardware model, serial number, system UUID,
      physical memory and processor information.

    - Virtualization information:
      Detection of virtual machines based on reported hardware model
      and manufacturer information.

    - Firmware information:
      Boot mode and Secure Boot status.

    - Disk and volume information:
      Logical volumes, drive or mount point, volume label, file system,
      cluster size, total capacity, free space, free space percentage,
      compression status and dirty-bit status.

      Physical disk information including disk number, model,
      serial number, capacity, partition style, bus type, media type,
      health status and operational status.

    - Network configuration:
      Complete output from "ipconfig /all", including network adapters,
      IP configuration, MAC addresses, DNS configuration, DHCP information
      and other network settings reported by Windows.

    - Local administrators:
      Direct members of the local Administrators group, including account
      or group name, object type, account source and SID.

    - Windows services:
      Service name, display name, current state, startup mode,
      delayed automatic start status, logon account and service dependencies.
      Automatic services that are not running are highlighted in the report.

    - Installed applications:
      Application name, version, publisher, reported installation date
      and installation directory, when this information is available
      in the Windows uninstall registry entries.

    The collected information is read-only and is written to a local
    HTML inventory report.

.AUTHOR
    Krzysztof Gerus

.VERSION
    2.0
#>

$startTime = Get-Date
######## Function Declare ########

function GetBase {
    [hashtable]$Machine = @{}
    
    # Query WMI objects (single call per class for better performance)
    $OS = Get-WmiObject -Class Win32_OperatingSystem
    $Hard = Get-WmiObject -Class Win32_ComputerSystem
    $Product = Get-WmiObject -Class Win32_ComputerSystemProduct
    $BIOS = Get-WmiObject -Class Win32_BIOS
    $TimeZone = Get-WmiObject -Class Win32_TimeZone
    $Processors = @(Get-WmiObject -Class Win32_Processor)

    # Operating System details
    $Machine.OS = $OS.Caption
    $Machine.OSArchitecture = $OS.OSArchitecture
    $Machine.Build = $OS.BuildNumber
    $Machine.Language = $OS.OSLanguage
    $Machine.InstallDate = $OS.InstallDate.Substring(0,8)
    $Machine.LocalTime = $OS.LocalDateTime
    $Machine.TimeZone = $TimeZone.Caption
    
    # Boot time and Uptime calculation
    $Machine.LastBoot = [System.Management.ManagementDateTimeConverter]::ToDateTime($OS.LastBootUpTime)
    $Machine.Uptime = ((Get-Date) - $Machine.LastBoot).Days

    # Hardware, Virtualization and UUID details
    $Machine.Manufacturer = $Hard.Manufacturer
    $Machine.Model = $Hard.Model
    $Machine.SerialNumber = $BIOS.SerialNumber
    $Machine.UUID = $Product.UUID
    
    # Improved virtualization detection (VMware, Hyper-V, Xen/AWS, KVM, VirtualBox)
    if ($Hard.Model -match "VMware|Virtual|HVM domU|KVM|QEMU|Xen") {
        $Machine.VM = $True
        $coreLabel = "vCPU"
    } else {
        $Machine.VM = $False
        $coreLabel = "Logical Cores"
    }

    # RAM and CPU details (clean formatting without Format-Table)
    $Machine.PhysicalMemory = Get-WmiObject -Class CIM_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object { [math]::Round(($_.Sum / 1GB), 2) }
    
    $cpuName = ($Processors[0].Name).Trim()
    $cpuCount = $Processors.Count
    $totalLogicalCores = ($Processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    
    if ($cpuCount -gt 1) {
        $Machine.CPUInfo = "$cpuName (x$cpuCount, $totalLogicalCores $coreLabel)"
    } else {
        $Machine.CPUInfo = "$cpuName ($totalLogicalCores $coreLabel)"
    }

    # Pending Reboot check via Registry
    $cbsReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $wuReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    $Machine.PendingReboot = ($cbsReboot -or $wuReboot)

    # Boot Mode (UEFI vs Legacy BIOS) and Secure Boot status
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        try {
            $secureBootStatus = Confirm-SecureBootUEFI -ErrorAction Stop
            $Machine.BootMode = "UEFI"
            $Machine.SecureBoot = $secureBootStatus
        } catch {
            # Confirm-SecureBootUEFI throws PlatformNotSupportedException on Legacy BIOS or non-UEFI VMs
            if ($_.Exception.Message -match "Cmdlet not supported on this platform") {
                $Machine.BootMode = "Legacy BIOS"
            } else {
                $Machine.BootMode = "UEFI"
            }
            $Machine.SecureBoot = "N/A"
        }
    } else {
        $Machine.BootMode = "Legacy BIOS / Unknown"
        $Machine.SecureBoot = "N/A"
    }

    return $Machine
}


#Info about local users
function GetLocalAdmins {
    try {
        $Members = @(
            Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop |
                Sort-Object Name
        )
    } catch {
        Write-Warning "Cannot collect local administrators: $($_.Exception.Message)"

        return [PSCustomObject]@{
            Success = $false
            Members = @()
            Error   = $_.Exception.Message
        }
    }

    # Read local users once and index them by SID.
    $LocalUsersBySID = @{}
    $LocalUsersReadOK = $false

    try {
        $LocalUsers = @(Get-LocalUser -ErrorAction Stop)

        foreach ($User in $LocalUsers) {
            $LocalUsersBySID[[string]$User.SID] = $User
        }

        $LocalUsersReadOK = $true
    } catch {
        Write-Warning "Cannot read local account status: $($_.Exception.Message)"
    }

    $Results = @(
        foreach ($Member in $Members) {
            $SID = [string]$Member.SID
            $Source = [string]$Member.PrincipalSource

            if ([string]::IsNullOrWhiteSpace($Source)) {
                $Source = "Unknown"
            }

            $Enabled = "N/A"

            if ($Member.ObjectClass -eq "User") {
                if ($LocalUsersBySID.ContainsKey($SID)) {
                    $Enabled = $LocalUsersBySID[$SID].Enabled
                } elseif (-not $LocalUsersReadOK) {
                    # Account status could not be checked.
                    $Enabled = "Unknown"
                } elseif (
                    $Source -eq "Local" -or
                    $Member.Name -like "$env:COMPUTERNAME\*"
                ) {
                    # Looks local, but no matching local user was found.
                    $Enabled = "Unknown"
                }
            } elseif ($Member.ObjectClass -ne "Group") {
                $Enabled = "Unknown"
            }

            [PSCustomObject]@{
                Name            = $Member.Name
                ObjectClass     = $Member.ObjectClass
                PrincipalSource = $Source
                SID             = $SID
                Enabled         = $Enabled
            }
        }
    )

    return [PSCustomObject]@{
        Success = $true
        Members = $Results
        Error   = ""
    }
}


## Disk Info

function GetDiskInfo {
    [hashtable]$DiskData = @{
        Volumes       = @()
        PhysicalDisks = @()
    }

    # 1. Collect Logical Volumes & Mount Points (DriveType 3 = Local Fixed Disk)
    $Volumes = Get-WmiObject -Class Win32_Volume -Filter "DriveType = 3" |
               Where-Object { $_.Name -notlike "\\?\Volume*" } |
               Sort-Object Name

    foreach ($Vol in $Volumes) {
        $SizeGB = [math]::Round($Vol.Capacity / 1GB, 2)
        $FreeGB = [math]::Round($Vol.FreeSpace / 1GB, 2)

        if ($Vol.Capacity -gt 0) {
            $FreePercent = [math]::Round(($Vol.FreeSpace / $Vol.Capacity) * 100, 1)
        } else {
            $FreePercent = 0
        }

        # Flag low disk space (< 15%) for HTML highlighting
        $IsLowSpace = ($FreePercent -lt 15)

        $DiskData.Volumes += [PSCustomObject]@{
            Drive       = $Vol.Name
            Label       = $Vol.Label
            FileSystem  = $Vol.FileSystem
            BlockSizeKB = [math]::Round($Vol.BlockSize / 1KB, 0)
            SizeGB      = $SizeGB
            FreeGB      = $FreeGB
            FreePercent = $FreePercent
            Compressed  = $Vol.Compressed
            DirtyBit    = $Vol.DirtyBitSet
            IsLowSpace  = $IsLowSpace
        }
    }

    # 2. Collect Physical Disks (with fallback for older OS versions without Storage module)
    if (Get-Command Get-Disk -ErrorAction SilentlyContinue) {
        $PhysDisks = Get-Disk | Sort-Object Number
        $StorageDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue

        foreach ($Disk in $PhysDisks) {
            # Match physical disk details (MediaType) if available
            $MatchedPhys = $StorageDisks | Where-Object { $_.DeviceId -eq $Disk.Number } | Select-Object -First 1
            $MediaType = if ($MatchedPhys -and $MatchedPhys.MediaType) { $MatchedPhys.MediaType } else { "Unspecified" }
            $SafeSerial = if ($Disk.SerialNumber) { ($Disk.SerialNumber).Trim() } else { "N/A" }

            $DiskData.PhysicalDisks += [PSCustomObject]@{
                Number         = $Disk.Number
                FriendlyName   = $Disk.FriendlyName
                SerialNumber   = $SafeSerial
                SizeGB         = [math]::Round($Disk.Size / 1GB, 2)
                PartitionStyle = $Disk.PartitionStyle
                BusType        = $Disk.BusType
                MediaType      = $MediaType
                HealthStatus   = $Disk.HealthStatus
                Operational    = ($Disk.OperationalStatus -join ", ")
            }
        }
    } else {
        # Fallback to WMI Win32_DiskDrive for Windows Server 2008 / 2008 R2
        $WmiDisks = Get-WmiObject -Class Win32_DiskDrive | Sort-Object Index
        foreach ($Disk in $WmiDisks) {
            $SafeSerial = if ($Disk.SerialNumber) { ($Disk.SerialNumber).Trim() } else { "N/A" }

            $DiskData.PhysicalDisks += [PSCustomObject]@{
                Number         = $Disk.Index
                FriendlyName   = $Disk.Model
                SerialNumber   = $SafeSerial
                SizeGB         = [math]::Round($Disk.Size / 1GB, 2)
                PartitionStyle = "N/A (Legacy OS)"
                BusType        = $Disk.InterfaceType
                MediaType      = $Disk.MediaType
                HealthStatus   = $Disk.Status
                Operational    = $Disk.Status
            }
        }
    }

    return $DiskData
}

function GetIPConfig {
    try {
        $Output = & "$env:SystemRoot\System32\ipconfig.exe" /all 2>&1
        $ExitCode = $LASTEXITCODE

        if ($ExitCode -ne 0) {
            throw "ipconfig failed with exit code $ExitCode."
        }

        return ($Output -join [Environment]::NewLine)
    } catch {
        Write-Warning "Cannot collect ipconfig: $($_.Exception.Message)"
        return "Unable to collect ipconfig /all output."
    }
}


#services
function GetServicesInfo {
    # Collect service configuration and current state.
    try {
        $Services = @(
            Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
                Sort-Object DisplayName
        )
    } catch {
        Write-Warning "Cannot collect services: $($_.Exception.Message)"

        return [PSCustomObject]@{
            Success = $false
            Services = @()
            Error = $_.Exception.Message
        }
    }

    # Collect service controllers once and index them by name.
    $ControllersByName = @{}

    try {
        $Controllers = @(Get-Service -ErrorAction Stop)

        foreach ($Controller in $Controllers) {
            $ControllersByName[$Controller.Name] = $Controller
        }
    } catch {
        Write-Warning "Cannot collect service dependencies: $($_.Exception.Message)"
    }

    $Results = @(
        foreach ($Service in $Services) {
            $DependsOn = "Unknown"

            if ($ControllersByName.ContainsKey($Service.Name)) {
                try {
                    $Dependencies = @(
                        $ControllersByName[$Service.Name].ServicesDependedOn |
                            Select-Object -ExpandProperty Name
                    )

                    $DependsOn = if ($Dependencies.Count -gt 0) {
                        $Dependencies -join "; "
                    } else {
                        "None"
                    }
                } catch {
                    Write-Warning "Cannot read dependencies for $($Service.Name): $($_.Exception.Message)"
                }
            }

            # Missing delayed-start information must not become False.
            $DelayedAutoStart = if (
                $null -ne $Service.DelayedAutoStart
            ) {
                $Service.DelayedAutoStart
            } else {
                "Unknown"
            }

            # Use a readable label in the report.
            $StartMode = if ($Service.StartMode -eq "Auto") {
                "Automatic"
            } else {
                $Service.StartMode
            }

            [PSCustomObject]@{
                Name             = $Service.Name
                DisplayName      = $Service.DisplayName
                State            = $Service.State
                StartMode        = $StartMode
                DelayedAutoStart = $DelayedAutoStart
                LogonAccount     = $Service.StartName
                DependsOn        = $DependsOn
            }
        }
    )

    return [PSCustomObject]@{
        Success = $true
        Services = $Results
        Error = ""
    }
}


##### aplikacje
function GetInstalledApplications {
    $Applications = @()
    $ReadErrors = @()

    $UninstallPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

    # Read both registry views on a 64-bit operating system.
    $RegistryViews = if ([Environment]::Is64BitOperatingSystem) {
        @(
            [Microsoft.Win32.RegistryView]::Registry64
            [Microsoft.Win32.RegistryView]::Registry32
        )
    } else {
        @(
            [Microsoft.Win32.RegistryView]::Registry32
        )
    }

    foreach ($View in $RegistryViews) {
        $BaseKey = $null
        $UninstallKey = $null

        try {
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                $View
            )

            $UninstallKey = $BaseKey.OpenSubKey($UninstallPath)

            # A missing Uninstall key means no entries in this view.
            if ($null -eq $UninstallKey) {
                continue
            }

            foreach ($SubKeyName in $UninstallKey.GetSubKeyNames()) {
                $AppKey = $null

                try {
                    $AppKey = $UninstallKey.OpenSubKey($SubKeyName)

                    if ($null -eq $AppKey) {
                        throw "Registry entry is no longer available."
                    }

                    $Name = [string]$AppKey.GetValue("DisplayName")

                    # Skip entries without an application name.
                    if ([string]::IsNullOrWhiteSpace($Name)) {
                        continue
                    }

                    $Version = [string]$AppKey.GetValue("DisplayVersion")
                    $Publisher = [string]$AppKey.GetValue("Publisher")
                    $InstallLocation = [string]$AppKey.GetValue("InstallLocation")
                    $RawDate = [string]$AppKey.GetValue("InstallDate")

                    # Convert yyyyMMdd dates; preserve other non-empty values.
                    $InstallDate = "Unknown"

                    if (-not [string]::IsNullOrWhiteSpace($RawDate)) {
                        $ParsedDate = [datetime]::MinValue

                        if ([datetime]::TryParseExact(
                            $RawDate.Trim(),
                            "yyyyMMdd",
                            [System.Globalization.CultureInfo]::InvariantCulture,
                            [System.Globalization.DateTimeStyles]::None,
                            [ref]$ParsedDate
                        )) {
                            $InstallDate = $ParsedDate.ToString("yyyy-MM-dd")
                        } else {
                            $InstallDate = $RawDate.Trim()
                        }
                    }

                    $Applications += [PSCustomObject]@{
                        Name = $Name.Trim()

                        Version = if (
                            [string]::IsNullOrWhiteSpace($Version)
                        ) {
                            "Unknown"
                        } else {
                            $Version.Trim()
                        }

                        Publisher = if (
                            [string]::IsNullOrWhiteSpace($Publisher)
                        ) {
                            "Unknown"
                        } else {
                            $Publisher.Trim()
                        }

                        ReportedInstallDate = $InstallDate

                        InstallLocation = if (
                            [string]::IsNullOrWhiteSpace($InstallLocation)
                        ) {
                            "Unknown"
                        } else {
                            $InstallLocation.Trim()
                        }
                    }
                } catch {
                    $Message = "Cannot read application entry [$View / $SubKeyName]: $($_.Exception.Message)"
                    $ReadErrors += $Message
                    Write-Warning $Message
                } finally {
                    if ($null -ne $AppKey) {
                        $AppKey.Dispose()
                    }
                }
            }
        } catch {
            $Message = "Cannot read installed applications [$View]: $($_.Exception.Message)"
            $ReadErrors += $Message
            Write-Warning $Message
        } finally {
            if ($null -ne $UninstallKey) {
                $UninstallKey.Dispose()
            }

            if ($null -ne $BaseKey) {
                $BaseKey.Dispose()
            }
        }
    }

$SortedApplications = @(
        $Applications | Sort-Object Name, Version
    )

    return [PSCustomObject]@{
        Success      = ($ReadErrors.Count -eq 0 -or $SortedApplications.Count -gt 0)
        Applications = $SortedApplications
        Error        = ($ReadErrors -join "; ")
    }
}

############## RAW DATA collection ################

# SystemInfo
Write-Host "Getting system information..."
$SystemConfig = GetBase

# Local Admins
Write-Host "Getting local administrators..."
$LocalAdminsConfig = GetLocalAdmins


# DiskInfo (Logical Volumes & Physical Disks)
Write-Host "Getting disk and volume information..."
$DiskConfig = GetDiskInfo

Write-Host "Getting network configuration..."
$IPConfigData = GetIPConfig

Write-Host "Getting services information..."
$ServicesConfig = GetServicesInfo

Write-Host "Getting installed applications..."
$AppsConfig = GetInstalledApplications

# Calculate script execution time before building the footer
$interval = New-TimeSpan -Start $startTime -End (Get-Date)



############## RAW DATA Input To  HTML format ###############

$objFormattedDate = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
$objHost = $env:COMPUTERNAME

Write-Host "Generating HTML report..."

# Start of HTML Document format with centralized CSS classes
$objHTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>$objHost - Audit Report</title>
    <style>
        body {
            font-family: Segoe UI, Arial, sans-serif;
        }
        h1 {
            font-weight: bold;
            font-size: 24px;
        }
        table {
            width: 100%;
            border: 1px solid black;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th {
            border-bottom: 1px solid #ddd;
            text-align: left;
            font-size: 15px;
            padding: 6px;
        }
        td {
            border-bottom: 1px solid #ddd;
            text-align: left;
            font-size: 12px;
            padding: 4px 6px;
        }
        .label {
            border-bottom: 1px solid #ddd;
            text-align: left;
            font-weight: bold;
            color: blue;
            font-size: 18px;
            padding: 8px 6px;
        }
        .key-col {
            width: 25%;
            font-weight: bold;
        }
        .alert-red {
            background-color: #ffcccc;
            color: #990000;
            font-weight: bold;
        }
        .alert-green {
            background-color: #ccffcc;
            color: #006600;
            font-weight: bold;
        }
        .info-blue {
    background-color: #dbeafe;
    color: #1e3a8a;
    font-weight: bold;
        }
        .raw-output {
            margin: 0;
            padding: 10px;
            font-family: Consolas, "Courier New", monospace;
            font-size: 12px;
            font-weight: normal;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            background-color: #f3f4f6;
            color: #111827;
                       }



    </style>
</head>
<body>
    <h1>${objHost}_${objFormattedDate}</h1>
"@

############# System Info Table #################

# Highlight BLUE values only when VM is explicitly Boolean True.
$VMValueClass = if (
    $SystemConfig["VM"] -is [bool] -and
    $SystemConfig["VM"] -eq $true
) {
    ' class="info-blue"'
} else {
    ''
}
# Apply .alert-red when a pending reboot is detected.
$PendingRebootRowClass = if (
    ([string]$SystemConfig["PendingReboot"]).Trim() -ieq "True"
) {
    ' class="alert-red"'
} else {
    ''
}
## create table
$objHTML += @"
    <table>
        <thead>
            <tr>
                <th colspan="2" class="label">SystemInfo</th>
            </tr>
        </thead>
        <tbody>
            <tr><td class="key-col">Operating System</td><td>$($SystemConfig["OS"])</td></tr>
            <tr><td class="key-col">OS Architecture</td><td>$($SystemConfig["OSArchitecture"])</td></tr>
            <tr><td class="key-col">Build Number</td><td>$($SystemConfig["Build"])</td></tr>
            <tr><td class="key-col">OS Language</td><td>$($SystemConfig["Language"])</td></tr>
            <tr><td class="key-col">Install Date</td><td>$($SystemConfig["InstallDate"])</td></tr>
            <tr><td class="key-col">Time Zone</td><td>$($SystemConfig["TimeZone"])</td></tr>
            <tr><td class="key-col">Virtual Machine</td><td$VMValueClass>$($SystemConfig["VM"])</td></tr>
            <tr><td class="key-col">Hardware Model</td><td$VMValueClass>$($SystemConfig["Model"])</td></tr>
            <tr><td class="key-col">Manufacturer</td><td$VMValueClass>$($SystemConfig["Manufacturer"])</td></tr>
            <tr><td class="key-col">Serial Number</td><td>$($SystemConfig["SerialNumber"])</td></tr>
            <tr><td class="key-col">UUID</td><td>$($SystemConfig["UUID"])</td></tr>
            <tr><td class="key-col">Boot Mode</td><td>$($SystemConfig["BootMode"])</td></tr>
            <tr><td class="key-col">Secure Boot</td><td>$($SystemConfig["SecureBoot"])</td></tr>
            <tr><td class="key-col">RAM</td><td>$($SystemConfig["PhysicalMemory"]) GB</td></tr>
            <tr><td class="key-col">CPU</td><td>$($SystemConfig["CPUInfo"])</td></tr>
            <tr><td class="key-col">Last Boot Time</td><td>$($SystemConfig["LastBoot"])</td></tr>
            <tr><td class="key-col">Uptime [days]</td><td>$($SystemConfig["Uptime"])</td></tr>
            <tr$PendingRebootRowClass><td class="key-col">Pending Reboot</td><td>$($SystemConfig["PendingReboot"])</td></tr>
        </tbody>
    </table>
"@

###########################################################################
### START: PASTE ADDITIONAL TABLES BELOW (e.g., Disks, Network, Services) ###
###########################################################################


############# Local Administrators Table #################

$LocalAdminRows = ""

if (-not $LocalAdminsConfig.Success) {
    $ErrorHTML = [System.Net.WebUtility]::HtmlEncode(
        [string]$LocalAdminsConfig.Error
    )

    $LocalAdminRows = "<tr><td colspan='4'>Unable to collect local administrators: $ErrorHTML</td></tr>"
} elseif ($LocalAdminsConfig.Members.Count -eq 0) {
    $LocalAdminRows = "<tr><td colspan='4'>No direct members returned.</td></tr>"
} else {
    foreach ($Member in $LocalAdminsConfig.Members) {
        $NameHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Member.Name
        )
        $TypeHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Member.ObjectClass
        )
        $SourceHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Member.PrincipalSource
        )
        $SIDHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Member.SID
        )

        $LocalAdminRows += @"
            <tr>
                <td>$NameHTML</td>
                <td>$TypeHTML</td>
                <td>$SourceHTML</td>
                <td>$SIDHTML</td>
            </tr>
"@
    }
}

$objHTML += @"
    <table>
        <thead>
            <tr>
                <th colspan="4" class="label">Local Administrators - Direct Members</th>
            </tr>
            <tr>
                <th>Account / Group</th>
                <th>Type</th>
                <th>Source</th>
                <th>SID</th>
            </tr>
        </thead>
        <tbody>
$LocalAdminRows
        </tbody>
    </table>
"@

############# Logical Volumes Table #################
$VolumeRows = ""
foreach ($Vol in $DiskConfig.Volumes) {
    # Apply .alert-red class if free space is below 15%
    $RowClass = if ($Vol.IsLowSpace) { ' class="alert-red"' } else { '' }
    
    # Apply .alert-red class if DirtyBit is set (chkdsk required)
    $DirtyClass = if ($Vol.DirtyBit -eq $True) { ' class="alert-red"' } else { '' }

    $VolumeRows += @"
            <tr$RowClass>
                <td><strong>$($Vol.Drive)</strong></td>
                <td>$($Vol.Label)</td>
                <td>$($Vol.FileSystem)</td>
                <td>$($Vol.BlockSizeKB) KB</td>
                <td>$($Vol.SizeGB) GB</td>
                <td>$($Vol.FreeGB) GB</td>
                <td>$($Vol.FreePercent)%</td>
                <td>$($Vol.Compressed)</td>
                <td$DirtyClass>$($Vol.DirtyBit)</td>
            </tr>
"@
}

$objHTML += @"
    <table>
        <thead>
            <tr>
                <th colspan="9" class="label">Disk Information - Logical Volumes</th>
            </tr>
            <tr>
                <th>Drive / Mount Point</th>
                <th>Label</th>
                <th>File System</th>
                <th>Cluster Size</th>
                <th>Total Size</th>
                <th>Free Space</th>
                <th>Free %</th>
                <th>Compressed</th>
                <th>Dirty Bit</th>
            </tr>
        </thead>
        <tbody>
$VolumeRows
        </tbody>
    </table>
"@

############# Physical Disks Table #################
$PhysicalDiskRows = ""
foreach ($Disk in $DiskConfig.PhysicalDisks) {
    # Apply .alert-red class if HealthStatus is not Healthy or OK
    $HealthClass = if ($Disk.HealthStatus -notmatch "Healthy|OK") { ' class="alert-red"' } else { '' }

    $PhysicalDiskRows += @"
            <tr>
                <td><strong>Disk $($Disk.Number)</strong></td>
                <td>$($Disk.FriendlyName)</td>
                <td>$($Disk.SerialNumber)</td>
                <td>$($Disk.SizeGB) GB</td>
                <td>$($Disk.PartitionStyle)</td>
                <td>$($Disk.BusType)</td>
                <td>$($Disk.MediaType)</td>
                <td$HealthClass>$($Disk.HealthStatus)</td>
                <td>$($Disk.Operational)</td>
            </tr>
"@
}

$objHTML += @"
    <table>
        <thead>
            <tr>
                <th colspan="9" class="label">Disk Information - Physical Disks</th>
            </tr>
            <tr>
                <th>Disk #</th>
                <th>Model / Friendly Name</th>
                <th>Serial Number</th>
                <th>Total Size</th>
                <th>Partition Style</th>
                <th>Bus Type</th>
                <th>Media Type</th>
                <th>Health Status</th>
                <th>Operational Status</th>
            </tr>
        </thead>
        <tbody>
$PhysicalDiskRows
        </tbody>
    </table>
"@


############# Network Configuration Table #################

# Encode collected text so HTML treats it as text, not markup.
$IPConfigHTML = [System.Net.WebUtility]::HtmlEncode($IPConfigData)

$objHTML += @"
    <table>
        <thead>
            <tr>
                <th class="label">Network Configuration - ipconfig /all</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><pre class="raw-output">$IPConfigHTML</pre></td>
            </tr>
        </tbody>
    </table>
"@
########## services

############# Services Table #################

$ServiceRows = ""

if (-not $ServicesConfig.Success) {
    $ErrorHTML = [System.Net.WebUtility]::HtmlEncode(
        [string]$ServicesConfig.Error
    )

    $ServiceRows = @"
            <tr>
                <td colspan="7">Unable to collect services: $ErrorHTML</td>
            </tr>
"@
} elseif ($ServicesConfig.Services.Count -eq 0) {
    $ServiceRows = @"
            <tr>
                <td colspan="7">No services returned.</td>
            </tr>
"@
} else {
    foreach ($Service in $ServicesConfig.Services) {
        # Highlight automatic services that are not Running.
        $ServiceRowClass = if (
            $Service.StartMode -eq "Automatic" -and
            $Service.State -ne "Running"
        ) {
            ' class="alert-red"'
        } else {
            ''
        }

        # Encode every value before inserting it into HTML.
        $NameHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Service.Name
        )

        $DisplayNameHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Service.DisplayName
        )

        $StateHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Service.State
        )

        $StartModeHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Service.StartMode
        )

        $DelayedHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Service.DelayedAutoStart
        )

        $LogonHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Service.LogonAccount
        )

        $DependsOnHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Service.DependsOn
        )

        $ServiceRows += @"
            <tr${ServiceRowClass}>
                <td>$NameHTML</td>
                <td>$DisplayNameHTML</td>
                <td>$StateHTML</td>
                <td>$StartModeHTML</td>
                <td>$DelayedHTML</td>
                <td>$LogonHTML</td>
                <td>$DependsOnHTML</td>
            </tr>
"@
    }
}

## Create table
$objHTML += @"
    <table>
        <thead>
            <tr>
                <th colspan="7" class="label">Services</th>
            </tr>
            <tr>
                <th>Name</th>
                <th>Display Name</th>
                <th>State</th>
                <th>Start Mode</th>
                <th>Delayed Start</th>
                <th>Log On As</th>
                <th>Depends On</th>
            </tr>
        </thead>
        <tbody>
$ServiceRows
        </tbody>
    </table>
"@

############# Installed Applications Table #################

$AppRows = ""



if (-not $AppsConfig.Success -and $ApplicationsConfig.Applications.Count -eq 0) {
    $ErrorHTML = [System.Net.WebUtility]::HtmlEncode(
        [string]$AppsConfig.Error
    )

    $AppRows = @"
            <tr>
                <td colspan="5" class="alert-red">Unable to collect installed applications: $ErrorHTML</td>
            </tr>
"@
} elseif ($AppsConfig.Applications.Count -eq 0) {
    $AppRows = @"
            <tr>
                <td colspan="5">No installed applications found.</td>
            </tr>
"@
} else {
    foreach ($App in $AppsConfig.Applications) {
        # Encode every value before inserting it into HTML
        $AppNameHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$App.Name
        )

        $AppVersionHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$App.Version
        )

        $AppPublisherHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$App.Publisher
        )

        $AppDateHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$App.ReportedInstallDate
        )

        $AppLocationHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$App.InstallLocation
        )

        $AppRows += @"
            <tr>
                <td><strong>$AppNameHTML</strong></td>
                <td>$AppVersionHTML</td>
                <td>$AppPublisherHTML</td>
                <td>$AppDateHTML</td>
                <td>$AppLocationHTML</td>
            </tr>
"@
    }

    # Append a warning row if partial registry read errors occurred
    if (-not [string]::IsNullOrWhiteSpace($AppsConfig.Error)) {
        $PartialErrorHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$AppsConfig.Error
        )

        $AppRows += @"
            <tr>
                <td colspan="5" class="alert-red">Warning (partial read errors): $PartialErrorHTML</td>
            </tr>
"@
    }
}

$objHTML += @"
    <table>
        <thead>
            <tr>
                <th colspan="5" class="label">Installed Applications ($($AppsConfig.Applications.Count))</th>
            </tr>
            <tr>
                <th>Application Name</th>
                <th>Version</th>
                <th>Publisher</th>
                <th>Install Date</th>
                <th>Install Location</th>
            </tr>
        </thead>
        <tbody>
$AppRows
        </tbody>
    </table>
"@



###########################################################################
### END: PASTE ADDITIONAL TABLES ABOVE                                  ###
###########################################################################

# Calculate script execution time before building the footer
$interval = New-TimeSpan -Start $startTime -End (Get-Date)

# Close HTML Document
$objHTML += @"
    <br>
    <i> Report generated in $($interval.Minutes)m $($interval.Seconds)s</i>
</body>
</html>
"@

# Export HTML report to file
$filename = "$env:COMPUTERNAME {0:yyyyMMdd-HHmm}" -f (Get-Date)
$objHTML | Out-File -FilePath ".\$filename.html" -Encoding UTF8

# $objHTML | Out-File -FilePath "\\1.1.1.1\share\folder\$filename.html" -Encoding UTF8
