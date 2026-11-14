<#
.SYNOPSIS
    Windows Server Inventory Report

.DESCRIPTION
    Collects configuration, hardware, network, software and operational
    information from a Windows system and generates an HTML inventory report.

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
      Logical volumes and mount points, volume label, file system,
      cluster size, total capacity, free space, free space percentage,
      compression status and dirty-bit status.

      Physical disk information including disk number, model,
      serial number, capacity, partition style, bus type, media type,
      health status and operational status.

    - Network configuration:
      Complete output from "ipconfig /all", including network adapters,
      IP configuration, MAC addresses, DNS configuration, DHCP information
      and other network settings reported by Windows.

    - WinHTTP proxy configuration:
      Current system WinHTTP proxy configuration collected using
      "netsh winhttp show proxy".

    - Routing information:
      Current IPv4 and IPv6 routing information collected using
      "route print", including active and persistent routes reported
      by Windows.

    - Listening TCP ports:
      TCP endpoints currently in the LISTEN state, including local IP
      address, port, IPv4/IPv6 address family, owning process ID,
      process name, process account and executable path when available.

    - Local administrators:
      Direct members of the local Administrators group, including account
      or group name, object type, account source and SID.

    - Windows services:
      Service name, display name, current state, startup mode,
      delayed automatic start status, logon account and service dependencies.

      Automatic services that are not currently running are highlighted
      in the HTML report for review.

    - Installed applications:
      Applications registered in the Windows Uninstall registry entries,
      including application name, version, publisher, reported installation
      date and installation directory when this information is available.

      On 64-bit systems, both 64-bit and 32-bit registry views are checked.

    - System event log:
      Recent Critical and Error events from the Windows System event log.

      The report includes event timestamp, Event ID, provider, Record ID,
      Process ID and event message. The maximum number of collected events
      is configurable by the script.

    The script performs inventory and diagnostic data collection only.
    The collected information is written to a local HTML report.

.HELP
    Quick execution from GitHub:

    The following PowerShell one-liner downloads the latest inventory.ps1
    script from GitHub to the local TEMP directory, executes it using
    Windows PowerShell and removes the downloaded script after execution.

    The generated HTML inventory report remains in the current working
    directory.

    Command:

    $u='https://raw.githubusercontent.com/Gallangher/OS_Infos/refs/heads/main/inventory.ps1'; $s=Join-Path $env:TEMP 'inventory.ps1'; Invoke-WebRequest $u -OutFile $s -UseBasicParsing -ErrorAction Stop; & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $s; Remove-Item $s -Force -ErrorAction SilentlyContinue

    Example:

    PS C:\Temp> <run the command above>

    The HTML report will be generated in:

    C:\Temp

    Requirements:
    - Internet access to raw.githubusercontent.com
    - PowerShell
    - Permission to execute the inventory commands used by the script

    Security note:
    The command downloads and immediately executes the current version
    of inventory.ps1 from the main GitHub branch. For controlled production
    environments, consider using a URL pinned to a specific Git commit
    or validating the downloaded script hash before execution.


    .AUTHOR
    Krzysztof Gerus

.VERSION
    2.3

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

function GetWinHttpProxy {
    try {
        $NetshPath = "$env:SystemRoot\System32\netsh.exe"

        if (-not (Test-Path -LiteralPath $NetshPath)) {
            throw "netsh.exe was not found: $NetshPath"
        }

        # Run netsh and capture both standard output and errors.
        $Output = & $NetshPath winhttp show proxy 2>&1
        $ExitCode = $LASTEXITCODE

        if ($ExitCode -ne 0) {
            throw "netsh failed with exit code $ExitCode. Output: $($Output -join ' ')"
        }

        if ($null -eq $Output -or $Output.Count -eq 0) {
            throw "netsh returned no output."
        }

        return [PSCustomObject]@{
            Success = $true
            Output  = ($Output -join [Environment]::NewLine)
            Error   = ""
        }
    }
    catch {
        Write-Warning "Cannot collect WinHTTP proxy configuration: $($_.Exception.Message)"

        return [PSCustomObject]@{
            Success = $false
            Output  = ""
            Error   = $_.Exception.Message
        }
    }
}


function GetRoutingTable {
    try {
        $RoutePath = "$env:SystemRoot\System32\route.exe"

        if (-not (Test-Path -LiteralPath $RoutePath)) {
            throw "route.exe was not found: $RoutePath"
        }

        # Run route print and capture both standard output and errors.
        $Output = & $RoutePath print 2>&1
        $ExitCode = $LASTEXITCODE

        if ($ExitCode -ne 0) {
            throw "route print failed with exit code $ExitCode. Output: $($Output -join ' ')"
        }

        if ($null -eq $Output -or $Output.Count -eq 0) {
            throw "route print returned no output."
        }

        return [PSCustomObject]@{
            Success = $true
            Output  = ($Output -join [Environment]::NewLine)
            Error   = ""
        }
    }
    catch {
        Write-Warning "Cannot collect routing table: $($_.Exception.Message)"

        return [PSCustomObject]@{
            Success = $false
            Output  = ""
            Error   = $_.Exception.Message
        }
    }
}

function GetListeningPorts {
    try {
        $Connections = @(
            Get-NetTCPConnection -State Listen -ErrorAction Stop
        )
    }
    catch {
        Write-Warning "Cannot collect listening TCP ports: $($_.Exception.Message)"

        return [PSCustomObject]@{
            Success     = $false
            Connections = @()
            Error       = $_.Exception.Message
        }
    }

    # Cache process information so the same PID is not queried repeatedly.
    $ProcessCache = @{}

    $Results = foreach ($Connection in $Connections) {

        $PIDNumber = $Connection.OwningProcess

        $ProcessName = "Unknown"
        $ProcessPath = "Unknown"
        $ProcessUser = "Unknown"

        if (-not $ProcessCache.ContainsKey($PIDNumber)) {

            try {
                $Process = Get-Process -Id $PIDNumber -ErrorAction Stop

                if ($Process.ProcessName) {
                    $ProcessName = $Process.ProcessName
                }

                try {
                    if ($Process.Path) {
                        $ProcessPath = $Process.Path
                    }
                }
                catch {
                    $ProcessPath = "Access denied / unavailable"
                }
            }
            catch {
                $ProcessName = "Unknown"
            }

            # Get process owner.
            try {
                $CimProcess = Get-CimInstance Win32_Process `
                    -Filter "ProcessId=$PIDNumber" `
                    -ErrorAction Stop

                if ($CimProcess) {
                    $Owner = Invoke-CimMethod `
                        -InputObject $CimProcess `
                        -MethodName GetOwner `
                        -ErrorAction Stop

                    if ($Owner.ReturnValue -eq 0 -and $Owner.User) {

                        if ($Owner.Domain) {
                            $ProcessUser = "$($Owner.Domain)\$($Owner.User)"
                        }
                        else {
                            $ProcessUser = $Owner.User
                        }
                    }
                }
            }
            catch {
                $ProcessUser = "Unknown"
            }

            $ProcessCache[$PIDNumber] = [PSCustomObject]@{
                Process = $ProcessName
                User    = $ProcessUser
                Path    = $ProcessPath
            }
        }

        $ProcessInfo = $ProcessCache[$PIDNumber]

        # Determine IPv4 / IPv6.
        $AddressFamily = if (
            $Connection.LocalAddress -match ":"
        ) {
            "IPv6"
        }
        else {
            "IPv4"
        }

        [PSCustomObject]@{
            IP            = $Connection.LocalAddress
            Port          = $Connection.LocalPort
            AddressFamily = $AddressFamily
            PID           = $PIDNumber
            Process       = $ProcessInfo.Process
            User          = $ProcessInfo.User
            Path          = $ProcessInfo.Path
        }
    }

    return [PSCustomObject]@{
        Success     = $true
        Connections = @(
            $Results | Sort-Object Port, IP
        )
        Error       = ""
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

function GetSystemEventErrors {
    param(
        [int]$MaxEvents = 20
    )

    try {
        if ($MaxEvents -lt 1) {
            throw "MaxEvents must be greater than zero."
        }

        $Events = @(
            Get-WinEvent `
                -FilterHashtable @{
                    LogName = "System"
                    Level   = 1, 2
                } `
                -MaxEvents $MaxEvents `
                -ErrorAction Stop
        )

        $Results = @(
            foreach ($Event in $Events) {
                $Message = if (
                    [string]::IsNullOrWhiteSpace([string]$Event.Message)
                ) {
                    "Message unavailable"
                } else {
                    # Replace line breaks to keep the HTML table compact.
                    ([string]$Event.Message).Trim() -replace "\r?\n", " "
                }

                [PSCustomObject]@{
                    TimeCreated  = $Event.TimeCreated
                    Id           = $Event.Id
                    ProviderName = $Event.ProviderName
                    Level        = $Event.LevelDisplayName
                    RecordId     = $Event.RecordId
                    ProcessId    = $Event.ProcessId
                    Message      = $Message
                }
            }
        )

        return [PSCustomObject]@{
            Success = $true
            Events  = $Results
            Error   = ""
        }
    }
    catch {
        # "No events were found" should produce an empty result,
        # rather than look like a script failure.
        if ($_.Exception.Message -match "No events were found") {
            return [PSCustomObject]@{
                Success = $true
                Events  = @()
                Error   = ""
            }
        }

        Write-Warning "Cannot collect System event errors: $($_.Exception.Message)"

        return [PSCustomObject]@{
            Success = $false
            Events  = @()
            Error   = $_.Exception.Message
        }
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


Write-Host "Getting WinHTTP proxy configuration..."
$WinHttpProxyConfig = GetWinHttpProxy

Write-Host "Getting routing table..."
$RoutingTableConfig = GetRoutingTable

Write-Host "Getting listening TCP ports..."
$ListeningPortsConfig = GetListeningPorts

Write-Host "Getting services information..."
$ServicesConfig = GetServicesInfo

Write-Host "Getting installed applications..."
$AppsConfig = GetInstalledApplications



Write-Host "Getting System event log errors..."
$SystemEventErrorsConfig = GetSystemEventErrors -MaxEvents 20


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

############# WinHTTP Proxy Table #################

if ($WinHttpProxyConfig.Success) {
    $WinHttpProxyHTML = [System.Net.WebUtility]::HtmlEncode(
        [string]$WinHttpProxyConfig.Output
    )
} else {
    $ProxyErrorHTML = [System.Net.WebUtility]::HtmlEncode(
        [string]$WinHttpProxyConfig.Error
    )

    $WinHttpProxyHTML = "Unable to collect WinHTTP proxy configuration: $ProxyErrorHTML"
}

$objHTML += @"
    <table>
        <thead>
            <tr>
                <th class="label">WinHTTP Proxy Configuration</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><strong>Command:</strong> netsh winhttp show proxy</td>
            </tr>
            <tr>
                <td>
                    <pre class="raw-output">$WinHttpProxyHTML</pre>
                </td>
            </tr>
        </tbody>
    </table>
"@

############# Routing Table #################

if ($RoutingTableConfig.Success) {

    $RoutingTableHTML = [System.Net.WebUtility]::HtmlEncode(
        [string]$RoutingTableConfig.Output
    )

} else {

    $RoutingErrorHTML = [System.Net.WebUtility]::HtmlEncode(
        [string]$RoutingTableConfig.Error
    )

    $RoutingTableHTML = "Unable to collect routing table: $RoutingErrorHTML"
}

$objHTML += @"
    <table>
        <thead>
            <tr>
                <th class="label">Routing Table</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><strong>Command:</strong> route print</td>
            </tr>
            <tr>
                <td>
                    <pre class="raw-output">$RoutingTableHTML</pre>
                </td>
            </tr>
        </tbody>
    </table>
"@


############# Listening TCP Ports Table #################

$ListeningPortRows = ""

if (-not $ListeningPortsConfig.Success) {

    $ErrorHTML = [System.Net.WebUtility]::HtmlEncode(
        [string]$ListeningPortsConfig.Error
    )

    $ListeningPortRows = @"
            <tr>
                <td colspan="7">Unable to collect listening TCP ports: $ErrorHTML</td>
            </tr>
"@

} elseif ($ListeningPortsConfig.Connections.Count -eq 0) {

    $ListeningPortRows = @"
            <tr>
                <td colspan="7">No listening TCP ports found.</td>
            </tr>
"@

} else {

    foreach ($Connection in $ListeningPortsConfig.Connections) {

        $IPHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Connection.IP
        )

        $PortHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Connection.Port
        )

        $AddressFamilyHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Connection.AddressFamily
        )

        $PIDHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Connection.PID
        )

        $ProcessHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Connection.Process
        )

        $UserHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Connection.User
        )

        $PathHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Connection.Path
        )

        $ListeningPortRows += @"
            <tr>
                <td>$IPHTML</td>
                <td><strong>$PortHTML</strong></td>
                <td>$AddressFamilyHTML</td>
                <td>$PIDHTML</td>
                <td>$ProcessHTML</td>
                <td>$UserHTML</td>
                <td>$PathHTML</td>
            </tr>
"@
    }
}

$objHTML += @"
    <table>
        <thead>
            <tr>
                <th colspan="7" class="label">Listening TCP Ports ($($ListeningPortsConfig.Connections.Count))</th>
            </tr>
            <tr>
                <th>Local IP</th>
                <th>Port</th>
                <th>IP Version</th>
                <th>PID</th>
                <th>Process</th>
                <th>Run As</th>
                <th>Executable Path</th>
            </tr>
        </thead>
        <tbody>
$ListeningPortRows
        </tbody>
    </table>
"@


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
#######

############# System Event Log Errors Table #################

$EventErrorRows = ""

if (-not $SystemEventErrorsConfig.Success) {

    $ErrorHTML = [System.Net.WebUtility]::HtmlEncode(
        [string]$SystemEventErrorsConfig.Error
    )

    $EventErrorRows = @"
            <tr>
                <td colspan="6">Unable to collect System event log errors: $ErrorHTML</td>
            </tr>
"@

} elseif ($SystemEventErrorsConfig.Events.Count -eq 0) {

    $EventErrorRows = @"
            <tr>
                <td colspan="6">No System errors found in the selected time period.</td>
            </tr>
"@

} else {

    foreach ($Event in $SystemEventErrorsConfig.Events) {

        $TimeHTML = [System.Net.WebUtility]::HtmlEncode(
            $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        )

        $IdHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Event.Id
        )

        $ProviderHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Event.ProviderName
        )

        $RecordIdHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Event.RecordId
        )

        $ProcessIdHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Event.ProcessId
        )

        $MessageHTML = [System.Net.WebUtility]::HtmlEncode(
            [string]$Event.Message
        )

        $EventErrorRows += @"
            <tr>
                <td>$TimeHTML</td>
                <td><strong>$IdHTML</strong></td>
                <td>$ProviderHTML</td>
                <td>$RecordIdHTML</td>
                <td>$ProcessIdHTML</td>
                <td>$MessageHTML</td>
            </tr>
"@
    }
}

$objHTML += @"
    <table>
        <thead>
            <tr>
                <th colspan="6" class="label">System Event Log - Last Errors ($($SystemEventErrorsConfig.Events.Count))</th>
            </tr>
            <tr>
                <th>Time</th>
                <th>Event ID</th>
                <th>Source</th>
                <th>Record ID</th>
                <th>Process ID</th>
                <th>Message</th>
            </tr>
        </thead>

        <tbody>
$EventErrorRows
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
