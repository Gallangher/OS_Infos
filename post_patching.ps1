<#
.SYNOPSIS
   The scipt checks for obvious patching issues.
    
.DESCRIPTION
    The scipt checks for obvious patching issues. A txt input file, containing the hostnames of the patched systems is used as input
    for this script.
    The first task is a search in the setup logs for failed or incomplete patches.

.Example.
    .\AfterPatchingChecks.ps1 c:\temp\list.txt
    
        
#>
 
Param (
    [Parameter(Mandatory=$true,HelpMessage="The text file with hostname of patched VMs")][string]$file
)

$today = Get-Date("01/01/2022")
$today = $today.Date

$logDir = "c:\temp\AfterpatchingChecks\"
$logFileName = "AfterpatchingChecks"
$VMWithConIssues = $null

#Function to generate logfilename - Start
################################################################################
Function GenerateLogFile([String]$logDir,[String]$logFileName)
{
    #date formating and logfile name building.
    $logDate = Get-Date -uformat "%y%m%d";
    $time = Get-Date -Format "dd/MM/yyyy HH:mm:ss";
    
    New-Variable LOGPATH -value "$logDir" -Option Constant;
    
    If (!(Test-Path $LOGPATH))
    {
        mkdir $LOGPATH;
    }

    $Script:LogFile = $LOGPATH + $logFileName + [String]$LogDate + ".log";
    
    # Header for Logs    
    $Header = "`n=====================================`r";
    $Header = $Header + "`nSCRIPT STARTED AT "+$Time+"`r";
    $Header = $Header + "`n=====================================`r";
    $Header = $Header + "`n`r";
    
    # create log file and log header
    If (!(Test-Path $LogFile))
    {
        $Header | Out-file -FilePath $LogFile;
    }
    Else 
    {
        $Header | Out-file -FilePath $LogFile -Append;
    }
    
}
#Function to generate logfilename - End
################################################################################

#Function to close the logfile - Start
################################################################################
Function CloseLogFile()
{
    $Time = Get-Date -Format "dd/MM/yyyy HH:mm:ss";
    # Header for Logs    
    $Footer = "`n=====================================`r";
    $Footer = $Footer + "`nSCRIPT ENDED AT "+$Time+"`r";
    $Footer = $Footer + "`n=====================================`r";
    $Footer = $Footer + "`n`r";
    
    $Footer | Out-file -FilePath $LogFile -Append;
}
#Function to close the logfile - END
#Log Informational message
################################################################################
Function LogInfo ($LogFile,$Message){
	$Now = get-date -format G; 
	$Message = "$Now`tI`t$Message";
	Write-Host $Message;
	$Message | Out-file -FilePath $LogFile -Append;
}

#Log Warning message
################################################################################
Function LogWarning ($LogFile,$Message) {
	$Now = get-date -format G ;
	$Message = "$Now`tW`t$Message";
	Write-Host $Message -ForegroundColor Yellow;
	$Message | Out-file -FilePath $LogFile -Append;
}

#Log Error message
################################################################################
Function LogError ($LogFile,$Message) {
	$Now = get-date -format G;
	$Message = "$Now`tE`t$Message";
	Write-Host $Message -ForegroundColor Red;
	$Message | Out-file -FilePath $LogFile -Append;
}


### -Begin script ###
#create log file
GenerateLogFile $logDir $logFileName;

if (test-path $file)
{
    $vms = Get-Content $file
    $logStr = "Input file exists - OK"
    Loginfo $LogFile $logStr 
}

Else
{
    $logStr = "Input file NOT exists - NOK"
    LogError $LogFile $logStr
    exit 1
} 

# set powerCli
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -confirm:$false -Scope user -ParticipateInCeip $false > $null;

# connect to Vcenters
Connect-VIServer SV81-esx-p100.nbs.ndis.be > $null;
Connect-VIServer SV83-esx-p100.nbs.ndis.be > $null;
 
foreach($vm in $vms)
{
    $error.Clear()
    $issues = 0

    $logStr = "Checking $vm..."
    Loginfo $LogFile $logStr

    # check vmtools status and snapshots
    $vmCheck = $null
    $error.Clear() 
    try
    {
        $vmCheck = Get-VM $vm -ErrorAction Stop | select name, powerstate, @{N="VMToolsStatus";E={$_.ExtensionData.Guest.ToolsStatus}} 
    }
    catch
    {
        $errmsg = "No vm for $vm found: $error" 
        LogError $LogFile $errmsg
        $logstr = "**********************************************************************************************************"
        Loginfo $LogFile $logstr
        $error.Clear()
        continue
        $error.Clear() 
    }
       
    if($vmCheck.VMToolsStatus -eq "toolsOk")
    {
        $logStr = "VMTools version -> OK"
        Loginfo $LogFile $logStr
    }
    else
    {
        $logStr = "VMTools version -> NOK!" + $vmCheck.VMToolsStatus + " Please upgrade the VMTools!"
        LogError $LogFile $logStr
        $issues++
    }

    #check for snapshots
    $snapshots = $null
    try
    {
        $error.clear()
        $snapshots = get-snapshot -vm $vm | select vm, created -ErrorAction stop
    }
    catch
    {
        $errmsg = "No snapshot for $vm found"  
        LogError $LogFile $errmsg
        $logstr = "**********************************************************************************************************"
        Loginfo $LogFile $logstr
        continue
    }

    if($snapshots)
    {
        $logStr = "Snapshots Not removed: "
        LogWarning $LogFile $logStr 
    
        foreach($snapshot in $snapshots)
        {
            $logstr = $snapshot 
            LogWarning $LogFile $logstr
        }
        $issue++
    }
    else
    {
        $logStr = "No snapshots found -> OK"
        Loginfo $LogFile $logStr

    }
    
    #check last boottime
    $infMess = "Get boottime $VM..." 
    Loginfo $LogFile $infMess;
    $error.Clear()
    try
    {
        $lastBootTime = Invoke-Command -ComputerName $vm -Command { (gwmi win32_operatingsystem).lastbootuptime } -ErrorAction:Stop
        $lastBootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($LastBootTime)
    }
    catch
    {
        if($VMWithConIssues -eq $null){
            $VMWithConIssues = @($vm)
            
            $errmsg = "$vm : $error" 
            LogError $LogFile $errmsg
            $logstr = "**********************************************************************************************************"
            Loginfo $LogFile $logstr
        } 
        else{ 
            $errmsg = "$vm : $error" 
            LogError $LogFile $errmsg
            $VMWithConIssues += $vm
            $logstr = "**********************************************************************************************************"
            Loginfo $LogFile $logstr
        }   
        
        $error.Clear()
        continue
    }
   
    if($lastBootTime.date -lt $today)
    {
        $errMessage = "Last boottime :" + $lastBootTime.Date +" -> NOK -> Today: $Today"
        LogError $LogFile $errMessage
        $issues++
    }
    Else
    {
        $infMess = "$lastBootTime -> OK" 
        Loginfo $LogFile $infMess;
    }
             
    # get KB state changes
    $changeEvents = $null
    $changeEvents = invoke-command -computername $vm -command {Get-WinEvent -FilterHashtable @{logname = ‘setup’; id = 1 } | ?{$_.timeCreated -gt $using:today -and !$_.message.contains('Superseded')} | select -ExpandProperty message}
    $changeEvents = $changeEvents | sort -Unique

    #get pending reboots
    $pendingReboots = $null
    $pendingReboots = invoke-command -computername $vm -command {Get-WinEvent -FilterHashtable @{logname = ‘setup’; id = 4 } | ?{$_.timeCreated -gt $using:today} | select -ExpandProperty message}
    $pendingReboots = $pendingReboots | sort -Unique

    #get succesfull installations
    $completeInstalls = $null
    $completeInstalls =  invoke-command -computername $vm -command {Get-WinEvent -FilterHashtable @{logname = ‘setup’; id = 2 } | ?{$_.timeCreated -gt $using:today} | select -ExpandProperty message}
    $completeInstalls = $completeInstalls | sort -Unique

    # check for discrepancies between change, and install logs.
    $logStr = "Checking for discrepancies in setup logs..."
    Loginfo $LogFile $logStr 

    $logStr = "Nr of patches to install: " + $changeEvents.count
    if($changeEvents.count -gt 0)
    {
        Loginfo $LogFile $logStr
    }
    else
    {
        LogError $LogFile $logstr
        $issues++
    }

    $logStr = "Nr of reboots required: " + $pendingReboots.count
    Loginfo $LogFile $logStr

    $logStr = "Nr of installed patches: " + $completeInstalls.count
    Loginfo $LogFile $logStr

    # check setup log discrepancies
    if($changeEvents.count -ne $completeInstalls.count)
    {
        $logStr = "Descrepancies found -> NOK -> Please check setup logs of $vm"
        LogError $LogFile $logstr

        $logStr = "Number of change events :" + $changeEvents.count + " Number of completed patches : " + $completeInstalls.count
        LogError $LogFile $logstr

        #change events
        $logStr = "Change events on $today : "
        LogWarning $LogFile $logStr 
    
        foreach($line in $changeEvents)
        {
            $logstr = $line
            LogWarning $LogFile $logstr
        }

        #pending reboots
        $logStr = "PendingReboot events  on $today : "
        LogWarning $LogFile $logStr 
    
        foreach($line in $pendingReboots)
        {
            $logstr = $line 
            LogWarning $LogFile $logstr
        }

        #complete installs
        $logStr = "Completed Install events  on $today : "
        LogWarning $LogFile $logStr 
    
        foreach($line in $completeInstalls)
        {
            $logstr = $line
            LogWarning $LogFile $logstr
        }

        $issues++
    }

    else
    {
        $logStr = "No discrepancies found -> OK"
        Loginfo $LogFile $logStr
    }

    # check trustedInstaller service
    $trustedInstaller = invoke-command -ComputerName $vm -command {get-service trustedInstaller | select *}

    if($trustedInstaller.StartType -eq 3 )
    {
        $logStr = "TrustedInstaller service startup type: Manual -> ok"
        Loginfo $LogFile $logStr
    }
    else
    {
        $logStr = "TrustedInstaller service startup type: " + $trustedInstaller.StartType + " -> NOK!"
        LogError $LogFile $logStr
        $issues++
    }

    if($trustedInstaller.Status -eq 1)
    {
        $logStr = "TrustedInstaller service status: Stopped -> ok"
        Loginfo $LogFile $logStr
    }
    else
    {
        $logStr = "TrustedInstaller service status: " + $trustedInstaller.Status + " -> NOK!"
        LogWarning $LogFile $logStr
        $issues++
    }  
     
    #check if vm patching was completed
    if($issues -gt 0)
    {
        $logStr = "$vm patching incomplete or failed -> Please check $vm"
        LogError $LogFile $logStr
    }
    else
    {
        $logStr = "$vm patching complete!"
        LogInfo $LogFile $logStr
    }  
       

    $logstr = "**********************************************************************************************************"
    Loginfo $LogFile $logstr
}
CloseLogFile
