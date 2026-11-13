

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




############## RAW DATA collection ################

# SystemInfo
Write-Host "Getting system information..."
$SystemConfig = GetBase

# DiskInfo (Logical Volumes & Physical Disks)
Write-Host "Getting disk and volume information..."
$DiskConfig = GetDiskInfo




# Calculate script execution time before building the footer
$interval = New-TimeSpan -Start $startTime -End (Get-Date)



############## RAW DATA Input 2 HTML format ###############

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
    </style>
</head>
<body>
    <h1>${objHost}_${objFormattedDate}</h1>
"@

############# System Info Table #################
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
            <tr><td class="key-col">Virtual Machine</td><td>$($SystemConfig["VM"])</td></tr>      
            <tr><td class="key-col">Hardware Model</td><td>$($SystemConfig["Model"])</td></tr>
            <tr><td class="key-col">Manufacturer</td><td>$($SystemConfig["Manufacturer"])</td></tr>      
            <tr><td class="key-col">Serial Number</td><td>$($SystemConfig["SerialNumber"])</td></tr>
            <tr><td class="key-col">UUID</td><td>$($SystemConfig["UUID"])</td></tr>
            <tr><td class="key-col">Boot Mode</td><td>$($SystemConfig["BootMode"])</td></tr>
            <tr><td class="key-col">Secure Boot</td><td>$($SystemConfig["SecureBoot"])</td></tr>
            <tr><td class="key-col">RAM</td><td>$($SystemConfig["PhysicalMemory"]) GB</td></tr>
            <tr><td class="key-col">CPU</td><td>$($SystemConfig["CPUInfo"])</td></tr>
            <tr><td class="key-col">Last Boot Time</td><td>$($SystemConfig["LastBoot"])</td></tr>
            <tr><td class="key-col">Uptime [days]</td><td>$($SystemConfig["Uptime"])</td></tr>
            <tr><td class="key-col">Pending Reboot</td><td>$($SystemConfig["PendingReboot"])</td></tr>
        </tbody>
    </table>
"@

###########################################################################
### START: PASTE ADDITIONAL TABLES BELOW (e.g., Disks, Network, Services) ###
###########################################################################

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
