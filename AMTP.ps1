#Atuomaticly Move To Production

##########MTP Automated Audit Script##########

<#UPDATENotes

08.02.2021 
v 2.06
- added summary of Atos tooling (EPO, BSA, Centreon, Flexera)
- fix issues with not supported commands
- backwards compatibility (works well without errors on 2008 servers),
- added how long report generation lasts

07.12.2020 
v.2.05
- generate output filename as $hostname + timestamp
this prevents the file from being overwritten (timestamp is unique)

09.10 Simple BSA check adjustment

13.08.2019 
- free disk space %
- windows licence
- mcafee agent + amcore version
- Active Directory / Workgroup
- Domain
- Uptime
- generate RSOP into separate html report
- list of installed apps
- list of automatic but not started services
- sccm agent simple check
- bsa agent simple check
- windows firewall profiles status

18.07.2019
-CheckSep now correctly checks last update on Windows 2k16 OS
-Added Port Check for SCCM checks
-ilo information now show only for physical machines
-DNS is now checked correctly



#>
#CheckPorts funkcja zwraca Tabele 2D SCCM Server/Port/Test[True/False]
<#Function CheckPorts {
$Array = @("EMEA","EMEA","APAC","APAC","AMER","AMER","APAC","APAC","AMER","AMER","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","APAC","APAC","APAC","APAC","APAC","APAC","APAC","APAC","APAC","AMER","AMER","AMER","AMER","AMER","AMER","AMER","AMER","AMER","EMEA","EMEA","APAC","APAC","AMER","AMER","EMEA","EMEA","AMER","AMER","AMER","AMER","APAC","APAC","APAC","APAC","EMEA","EMEA","EMEA","EMEA","EMEA","EMEA","AMER","AMER","APAC","APAC"),@("xspw10b465p.pharma.aventis.com","xspw10b465p.pharma.aventis.com","xspw10b465p.pharma.aventis.com","xspw10b465p.pharma.aventis.com","xspw10b467b.pharma.aventis.com","xspw10b467b.pharma.aventis.com","xspw10b468k.pharma.aventis.com","xspw10b468k.pharma.aventis.com","xspw10b468k.pharma.aventis.com","xspw10b468k.pharma.aventis.com","xspw10b781k.pharma.aventis.com","xspw10b781k.pharma.aventis.com","xspw10t629p.pharma.aventis.com","xspw10t629p.pharma.aventis.com","xspw10t630x.pharma.aventis.com","xspw10t630x.pharma.aventis.com","xspw10t633w.pharma.aventis.com","xspw10t633w.pharma.aventis.com","xspw10t633w.pharma.aventis.com","xspw10t634b.pharma.aventis.com","xspw10t634b.pharma.aventis.com","xspw10t634b.pharma.aventis.com","xspw10t635k.pharma.aventis.com","xspw10t635k.pharma.aventis.com","xspw10t635k.pharma.aventis.com","xspw10t897c.pharma.aventis.com","xspw10t897c.pharma.aventis.com","xspw10t898p.pharma.aventis.com","xspw10t898p.pharma.aventis.com","xspw10t898p.pharma.aventis.com","xspw10t900p.pharma.aventis.com","xspw10t900p.pharma.aventis.com","xspw10t901w.pharma.aventis.com","xspw10t901w.pharma.aventis.com","xspw10w202b.pharma.aventis.com","xspw10w202b.pharma.aventis.com","xspw10w204t.pharma.aventis.com","xspw10w204t.pharma.aventis.com","xspw10w204t.pharma.aventis.com","xspw10w205a.pharma.aventis.com","xspw10w205a.pharma.aventis.com","xspw10w206f.pharma.aventis.com","xspw10w206f.pharma.aventis.com","xspw50a367b.pharma.aventis.com","xspw50a367b.pharma.aventis.com","xspw50a371k.pharma.aventis.com","xspw50a371k.pharma.aventis.com","xspw50a375s.pharma.aventis.com","xspw50a375s.pharma.aventis.com","xspw50k340c.pharma.aventis.com","xspw50k340c.pharma.aventis.com","xspw50S403c.pharma.aventis.com","xspw50S403c.pharma.aventis.com","xspw50s404p.pharma.aventis.com","xspw50s404p.pharma.aventis.com","xspw50s405w.pharma.aventis.com","xspw50s405w.pharma.aventis.com","xspw50s406b.pharma.aventis.com","xspw50s406b.pharma.aventis.com","xspw50s407k.pharma.aventis.com","xspw50s407k.pharma.aventis.com","xspw50s408t.pharma.aventis.com","xspw50s408t.pharma.aventis.com","xspw50s509f.pharma.aventis.com","xspw50s509f.pharma.aventis.com","XSPW50S855P.pharma.aventis.com","XSPW50S855P.pharma.aventis.com","xspw50s856w.pharma.aventis.com","xspw50s856w.pharma.aventis.com"),@("443","8014","8014","443","8014","443","8014","443","8014","443","443","8014","80","443","80","443","80","443","8530","80","443","8530","80","443","8530","80","443","80","443","8530","80","443","80","443","80","443","80","443","8530","80","443","80","443","80","443","80","443","80","443","80","443","8014","443","8014","443","8014","443","8014","443","443","8014","443","8014","443","8014","8014","443","8014","443"),@()
    for($i = 0;$i -lt $Array[0].Length;$i++)
    {
        try
        {
            (new-object Net.Sockets.TcpClient).Connect($Array[1][$i],$Array[2][$i])
            $Array[3] += $True
        }
        catch
        {
            $Array[3] += $False
        }
    }
    $array.Length
    Return $Array
}

#>

#Get-ILOinfo Funkcja zwraca IP Firmware I versje ilo

function Get-IloInfo {
    [hashtable]$return = @{}
    Start-Process -filepath "C:\Program Files\HP\hponcfg\hponcfg.exe" -ArgumentList '/w out.xml'
    $Path = ".\out.xml"
    $XPath = "//MOD_NETWORK_SETTINGS"
    $nodes = Select-Xml -Path $Path -XPath $Xpath | Select-Object –ExpandProperty "node"
    $node = $nodes.IP_ADDRESS | Format-Table -HideTableHeaders | out-string 
    $iloip = $node.trim()
    $doc = New-Object System.Xml.XmlDocument
    $doc.Load("http://$iloip/xmldata?item=all")
    #Tutaj mozna dodac pare wartosci.

    $return.iloip = $iloip
    $return.firmware = $doc.RIMP.mp.fwri
    $return.ver = $doc.rimp.mp.pn
    
    return $return 
}
#funkcja testujaca SCCM'a

<#function TESTsccm {
        [hashtable]$OutSCCM = @{}
        $name = hostname
        [string]$gstring = get-content C:\Windows\SMSCFG.ini | Select-String "SMS Unique Identifier=GUID"
        $outsccm.LGUID = $gstring.Substring(22).trim()
        $objSCCM = Get-WmiObject -ComputerName "xspw10w200p.pharma.aventis.com" -Namespace "Root\SMS\Site_P00" -Class 'SMS_R_SYSTEM' -Filter "Name='$name'" 
        $sgstring = $objSCCM |select SMSuniqueIdentifier | ft -HideTableHeaders |out-string | Select-String "GUID"
        $OutSCCM.SGUID = $sgstring.ToString().Trim()
        $outsccm.Cver = $objSCCM |select ClientVersion | ft -HideTableHeaders | out-string
        $outsccm.obsolete = $objSCCM |select Obsolete | ft -HideTableHeaders | out-string
        $OutSCCM.GUID = $LGUID.Substring(22)
        $OutSCCM.Match = If($outsccm["LGUID"] -eq $outsccm["SGUID"]){$True}Else{$False}
        return $OutSCCM
    }
#>

#simple agents check
Function SimpleSCCMcheck {
if (get-content -ErrorAction SilentlyContinue C:\Windows\SMSCFG.ini | Select-String "SMS Unique Identifier=GUID") {$sccmstate = "Installed"} else {$sccmstate = "Not-installed"}
Return $sccmstate
}

Function SimpleBSAcheck {
$bsastatus = (((Get-Service | Where-Object {$_.Name -like "rscd*"}).Status))
Return $bsastatus
}


#Funkcja CheckSEP zwraca Czy SEP Jest sainstalowany .Installed (True/False) i czy jest aktualny .Status (True/False) 
function CheckSep {
    [hashtable]$SEPOut =@{}
    $7daysago = (get-date).AddDays(-7)
    $key = 'HKLM:SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion\SharedDefs\SDSDefs'
    if (test-path $key){out-null}else{$key = 'HKLM:SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion\SharedDefs'} 
    $sepout.ver = get-itemproperty -ErrorAction SilentlyContinue -path 'HKLM:SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion' -name PRODUCTVERSION | Select-Object PRODUCTVERSION | Format-Table -HideTableHeaders | out-string
    #Test for registry key path and execute if neccessary
    if (test-path -path $key)
        {
        $Installed = $True
        $path = (Get-ItemProperty -Path $key -Name DEFWATCH_10).DEFWATCH_10
        $writetime = [datetime](Get-ItemProperty -Path $path -Name LastWriteTime).lastwritetime
        if($writetime -gt $7daysago){$Status = $True} else {$Status = $False}
    }
    else
    {
        $Installed = $False
        $Status = $False
    }
    $SepOut.Status = $Status
    $SepOut.Installed = $Installed

    return $SEPOut
}

#JAC
#Funkcja CheckMC zwraca status instalacji i aktualizacji McAfee AV (warto dopracowac test-path czy w ogole jest instalacja)
function CheckMC {
    [hashtable]$MCOut =@{}
    $7daysago = (get-date).AddDays(-7)
    $key = 'HKLM:\SOFTWARE\McAfee\Agent'

    $mcafee = get-itemproperty HKLM:\software\mcafee\avsolution\DS\DS

# if (test-path $key){out-null}else{$key = 'HKLM:SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion\SharedDefs'} 
    $mcout.ver = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object {$_.DisplayName -like "McAfee Endpoint Security Platform*"}).displayversion
    #Test for registry key path and execute if neccessary
    if (test-path -path $key)
    {
        $Installed = $True
        $path = (get-itemproperty -Path $key -Name InstallPath).InstallPath
        $writetime = [datetime]($mcafee).szContentCreationDate
        $MCOut.AMCore = ($mcafee).dwContentMajorVersion
        if($writetime -gt $7daysago){$Status = $True} else {$Status = $False}
    }
    else
    {
        $Installed = $False
        $Status = $False}
    $MCOut.Status = $Status
    $MCOut.Installed = $Installed
    $MCOut.amcoredate = ($mcafee).szContentCreationDate
    $MCOut.Path = $path

    return $MCOut
}

#JAC
#Funkcja sprawdza czy server jest w domenie/grupie roboczej oraz fqdn domeny
function CheckDomain {
    [hashtable]$Domain =@{}
    $Domain.D1 = ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) 
    $Domain.W1 = ((Get-WmiObject -Class Win32_ComputerSystem).Workgroup)
    $Domain.fqdn = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

Return $Domain
}

#JAC
#Funkcja sprawdza status licencji Microsoft i kanal aktywacji 
function CheckLicence {
    [hashtable]$Licence =@{}
    $licenses=@{0="Unlicensed"; 1="Licensed"; 2="OOBGrace"; 3="OOTGrace"; 4="NonGenuineGrace"; 5="Notification"; 6="ExtendedGrace"}
    
    
    #$r=Get-CimInstance -Class SoftwareLicensingProduct |Where {$_.ApplicationID -eq "55c92734-d682-4d71-983e-d6ec3f16059f" -AND $_.PartialProductKey -ne $null}
    $r=get-wmiobject SoftwareLicensingProduct | Where-Object {$_.ApplicationID -eq "55c92734-d682-4d71-983e-d6ec3f16059f"-AND $null -ne $_.PartialProductKey }
    #$LicenceStatus = $licenceStatus[[int]$r.LicenseStatus]
    if(($r | Measure-Object).Count -gt 1) {$r = $r[0]}
        
	$statusdescription = $licenses[[int]$r.LicenseStatus]
	$Licence.Status = $statusdescription
    #$LicenceDetails = (Get-WmiObject -Class SoftwareLicensingProduct  | Where PartialProductKey )
    #$Licence.Key = (Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey 
    #$Licence.StatusCode = $r.LicenceStatus
    $Licence.Channel = $r.ProductKeyID
    $Licence.Description = $r.Description

    Return $Licence
}



function CheckLicence2 {
    [hashtable]$Licence =@{}
    #$licenses=@{0="Unlicensed"; 1="Licensed"; 2="OOBGrace"; 3="OOTGrace"; 4="NonGenuineGrace"; 5="Notification"; 6="ExtendedGrace"}
    $r=Get-CimInstance -Class SoftwareLicensingProduct |Where-Object {$_.ApplicationID -eq "55c92734-d682-4d71-983e-d6ec3f16059f" -AND $null -ne $_.PartialProductKey}
    $LicenceStatus = $licenseStatus[[int]$r.Licenses] 
    $Licence.Status = $LicenceStatus
    #$LicenceDetails = (Get-WmiObject -Class SoftwareLicensingProduct  | Where PartialProductKey )
    $Licence.Key = (Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey 
    $Licence.StatusCode = $r.LicenceStatus
    $Licence.Channel = $r.ProductKeyChannel
    $Licence.Description = $r.Description

    Return $Licence
}

function CheckAtosTooling{
    $curr_path = $pwd
    $EPO = @{}
    $BSA=@{}
    $Centreon = @{}
    $Flexera =@{}
    $to_return = @{}
    if(Get-Service RSCDsvc -ErrorAction SilentlyContinue)
    {
        Write-Host "`t[+] TSSA Agent is installed"

        $BSA['Status'] = (Get-Service RSCDsvc).Status
        $registry = Get-ItemProperty "HKLM:\SOFTWARE\BladeLogic\RSCD Agent"
        $BSA['InstalledVersion'] = $registry.CurrentVersion
        $BSA['BSA_User'] = $registry.BladeLogicRSCDUser
        $BSA['Agent_Home'] = $registry.AgentHome
        $to_return['BSA']=$BSA
    }
    else
    {
        Write-Host "`t[-] TSSA not installed"
    }
    #EPO
    if(Get-Service masvc -ErrorAction SilentlyContinue)
    {
        Write-Host "`t[+] McAfee Agent is installed"
        if(Test-Path "C:\Program Files\McAfee\Agent")
        {
            Set-Location "C:\Program Files\McAfee\Agent"
        }
        else
        {
            if(Test-Path "C:\Program Files (x86)\McAfee\Agent")
            {
                Set-Location "C:\Program Files (x86)\McAfee\Agent"
            }
            else
            {
                Set-Location "C:\Program Files (x86)\McAfee\Common Framework"
            }
            
        }
        $cmd = .\cmdagent.exe /i
        $EPO['Status']= (Get-Service masvc).Status
        $EPO['AgentVersion'] = $cmd[2].Split(':')[1].Trim()
        $EPO['AgentHome'] = $cmd[6].Split(':')[1].Trim() + $cmd[6].Split(':')[2].Trim()
        $EPO['ServerList'] = $cmd[9].Split(':')[1].Trim()
        $EPO['LastUsed'] = $cmd[11].Split(':')[1].Trim()
        $EPO['LastPolicyUpdate'] = [datetime]::ParseExact($cmd[13].Split(':')[1].Trim(), 'yyyyMMddHHmmss', $null).ToString('yyyy-MM-dd HH:mm:ss')
        $EPO['EPOVersion'] = $cmd[14].Split(':')[1].Trim()
        $to_return['EPO'] = $EPO
        Set-Location $curr_path
    }
    else
    {
        Write-Host "`t[-] McAfee Agent is not installed"
    }
    if(Get-Service nscp -ErrorAction SilentlyContinue)
    {
        Write-Host "`t[+] Centreon Agent is installed"
        $Centreon['Service'] = (Get-Service nscp).Status

        # Removed, cause Win32_product enumerates and validates all apllication, not just enumerates
        #$Centreon['AgentVersion'] = (Get-WmiObject Win32_product | Where-Object {$_.Name -match "NSClient.*"}).Version
        $Centreon['AgentVersion'] = (get-childitem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | where-object {($_.GetValue("DisplayName")) -like "*NSClient*"}).GetValue("DisplayVersion")
        if(Test-Path 'C:\Program Files\NSClient++')
        {
            $Centreon['AgentHome'] = "C:\Program Files\NSClient++"
        }
        else
        {
            $Centreon['AgentHome'] = "C:\Program Files (x86)\NSClient++"
        }
        $to_return['Centreon'] = $Centreon
    }
    else
    {
        Write-Host "`t[-] Centreon Agent is not installed"
    }
    if(Get-Service ndinit -ErrorAction SilentlyContinue)
    {
        Write-Host "`t[+] Flexera Agent is installed"
        $Flexera['Service'] = (Get-Service ndinit).Status
        $Flexera['AgentVersion'] = (Get-ItemProperty  "HKLM:\SOFTWARE\Wow6432Node\ManageSoft Corp\ManageSoft\" -Name ETCPVersion).ETCPVersion
        $Flexera['AgentHome'] = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\ManageSoft Corp\ManageSoft" -Name ETCPInstallDir).ETCPInstallDir
    }
    else 
    {
        Write-Host "`t[-] Flexera Agent is not installed"
    }
    Return $to_return

}
#GetBase z WMI - mozna dodac jakies wartosci w razie potrzeby, zwraca hashtable z istotnymi informacjami dla MTP= Return .OS = Operating System/ .Hardware = Manufacturer/ .VM = True/False if VM/ .installdate
Function GetBase{
    [hashtable]$Machine = @{}
    $OS = Get-WmiObject Win32_OperatingSystem 
    $Hard = Get-WmiObject Win32_ComputerSystem
    $Machine.PhysicalMemory = Get-WmiObject CIM_PhysicalMemory| Measure-Object -Property capacity -sum | ForEach-Object {[math]::round(($_.sum / 1GB),2)}
    
    $Machine.CPUInfo = Get-WmiObject Win32_Processor | Select-Object name | Format-Table -HideTableHeaders | out-string
    $Machine.Manufacturer = $OS.Manufacturer
    $Machine.Model = $Hard.Model
    if($Machine["Model"] -eq "VMware Virtual Platform"){$isVM = $True}else{$isVM = $False}
    $Machine.OS = $OS.Caption
    $Machine.VM = $isVM
    
    $Machine.InstallDate = $Os.InstallDate.substring(0,8)
    $Machine.Language = $OS.OSLanguage 
    $Machine.LocalTime = $OS.LocalDateTime
    $Machine.Build = $OS.BuildNumber
    $Machine.LastBoot = [System.Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject WIN32_OperatingSystem | Select-Object -ExpandProperty LastBootuptime))
    $Machine.Uptime = ((Get-Date) - $Machine.LastBoot).Days

    return $Machine
}

#Function IPCheck returns $_.IP (IPv4 address) $_.Mask (Subnet Mask) $_.Gateway (default gateway)
function IPCheck {
    $networks= get-wmiobject win32_networkadapterconfiguration -filter "macaddress <> NULL AND ipenabled=TRUE" | Where-Object {($_.ipaddress)}                
    #$networkadapters=@()
    #$wynik_Network=@()
    $allinone
    foreach ($network in $networks)
    {
        #$networkadapters = get-wmiobject win32_networkadapter -filter "macaddress='$($network.macaddress)'" #| sort macaddress -unique  | select @{N="Name";E={$_.netconnectionid}}, `
        <#@{N="Description";E={$network.description}}, `
        @{N="IP";E={$network.ipaddress -join ", "}}, `
        @{N="Default_Gateway";E={$network.defaultipgateway -join ", "}}, `
        @{N="Mask";E={$network.IPSubnet -join ","}}, `
        @{N="DNSIPS";E={$network.DNSServerSearchOrder -join ", "}}, `
        @{N="DNSName";E={$network.DNSDomainSuffixSearchOrder -join ", "}},
        @{N="MACAddress";E={$network.MACAddress}}
		$wynik_Network+= $networkadapters
        #>
        $allinone =  $allinone + "<tr> <td> IP <br> Mask <br> Gateway <br> DNS <br> Adapter type </td> <td> "  + $network.ipaddress + "<br>" + $network.IPSubnet + "<br>" + $network.defaultipgateway + "<br>" + $network.DNSServerSearchOrder + "<br>" + $network.Description + "</td></tr>"
    }
    
    #$wynik_Network= $networkadapters 
    Return $allinone
}
#Get computer membership from ADSI (returns string with group name in per line)
function Get-PCMembership {
    Write-Host "Getting Directory Services information..."
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
    $objSearcher.Filter = "(&(objectCategory=Computer)(SamAccountname=$($env:COMPUTERNAME)`$))"
    $objSearcher.SearchScope = "Subtree"
    $computer = $objSearcher.FindOne().properties.memberof
    
    return $computer
    }
$startTime = Get-Date
#Get Local Admins To Var $LocalAdmins
Write-Host "Getting local admins information..."
$LocalAdmins = ([ADSI]"WinNT://localhost/Administrators,group").Members() | ForEach-Object { ([ADSI]$_).Path.Substring(8) }
##############RAW DATA collection################

#Ipconfig
Write-Host "Getting network information..."
$IPconf = IPCheck
#SystemInfo
Write-Host "Getting system information..."
$SystemConfig = GetBase
#Simple SCCM agent check
Write-Host "Getting SCCM agent info..."
$sccmstate = SimpleSCCMcheck
#Simple BSA agent check
Write-Host "Getting BSA agent info..."
$bsastate = SimpleBSAcheck
#Disks
Write-Host "Getting volumes information..."
$objDiskInfo = Get-WmiObject -Query "Select * from Win32_LogicalDisk where DriveType = '3'"
#Computer Domain Groups#
$pc = Get-PCMembership
#PageFile#
Write-Host "Getting pagefile information..."
$objPageFile = Get-WmiObject Win32_PageFileusage |  Select-Object Name,AllocatedBaseSize,PeakUsage
#Get Wmi Information into Array
Write-Host "Getting syslog information..."
$EventError = get-eventlog -LogName system -EntryType Error -Newest 20 #| select TimeGenerated, EntryType, Source, InstanceID, Message | ft -AutoSize -HideTableHeaders
#	13. reboot management + all reboots list
#All Stops
$eventStops = get-eventlog -logname System -InstanceId 2147489654 -Newest 5 -ErrorAction SilentlyContinue #| select TimeGenerated, Message |ft -AutoSize -HideTableHeaders 
#All Start
$eventStarts = get-eventlog -logname System -InstanceId 2147489653 -Newest 5 -ErrorAction SilentlyContinue #| select TimeGenerated, Message |ft -AutoSize -HideTableHeaders
#RestartTriggered
$RestartTrigger = get-eventlog -logname System -InstanceId 2147484722 -Newest 5 -ErrorAction SilentlyContinue #| select TimeGenerated, UserName, Messsage |ft -AutoSize -HideTableHeaders
#Teaming information
Write-Host "Getting NIC teaming information..."
$Teaming = ""
if(Get-Command Get-NetLbfoTeamMember -ErrorAction SilentlyContinue)
{
    $Teaming = Get-NetLbfoTeamMember | Select-Object InterfaceAlias, OperationalStatus, FailureReason, TransmitLinkSpeed, InterfaceDescription, Team  
}
else 
{
    $Teaming = "No OS NIC Teaming on older than 2012"
}
#Net Share 
Write-Host "Getting Shares information..."
$Shares = Get-WmiObject Win32_Share | Select-Object Name, Path
#scheduled tasks 
Write-Host "Getting scheduled tasks information..."
$schtasks = schtasks.exe /query /v /fo:csv
#ilo info - further in script with IF(VM) condition
#         $IloInfo = Get-IloInfo
#Check Sep
Write-Host "Getting SEP information..."
$sepout = CheckSep
#Check McAfee
Write-Host "Getting McAfee information..."
$mcout = CheckMC
#Check Domain and workgroup
Write-Host "Getting Domain information..."
$Domain = CheckDomain

#check licence and activation
Write-Host "Getting MS licence information..."
$Licence = CheckLicence
#SCCM Test (SCCMtest is output regarding sccm agent, portCheck is 2d array with 
#$SCCMTest = TESTsccm
#$PortCheck =@(),@(),@(),@()
#$PortCheck = CheckPorts
#Services list
Write-Host "Getting services information..."
$all_services = Get-Service | Select-Object Name,DisplayName,ServiceName,StartType,Status 
$stopped_services = $all_services | where-Object {($_.StartType -eq 'Automatic') -and  ($_.Status -ne 'Running')}
#Hotfix info
Write-Host "Getting hotfixes information..."
$FixHot = get-hotfix | Select-Object HotFixID, InstalledOn, InstalledBy | Sort-Object InstalledOn -Descending
#JAC windows advanced firewall profiles status
Write-Host "Getting windows firewall information..."
$firewall=""
if(Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)
{
    $firewall = Get-NetFirewallProfile | Select-Object name,enabled 
}
else 
{
    $firewall = @{}
    $temp = netsh advfirewall show allprofiles
    $firewall['Domain'] = $temp[3].Split(' ')[-1]
    $firewall['Private'] = $temp[20].Split(' ')[-1]
    $firewall['Public'] = $temp[37].Split(' ')[-1]
}
#JAC Applications installed info
Write-Host "Getting installed applications information..."
$Apps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallDate
#JAC Getting GPO result
#Atos Tooling info and health
Write-Host "Getting Atos Tooling information..."
$tooling = CheckAtosTooling
Write-Host "Getting RSOP results ..."
#$gpresult_file = "\\155.45.163.189\ts_emea$\_public\a562569\$env:COMPUTERNAME-rsop.html"
$gpresult_file = ".\$env:COMPUTERNAME-rsop.html"
if (Test-Path $gpresult_file) {Remove-Item $gpresult_file}
gpresult /H $gpresult_file



#RSOP
#$RSOP = Get-CimInstance -Namespace root\rsop\computer -Query "select * from RSOP_PolicySetting" | select creationTime, GPOID, Name, SOMID, Command, RegistryKey, Value

##############RAW DATA Input 2 HTML format###############

$objFormattedDate=get-date -f "dd-MM-yyyy HH:mm:ss"
#$objTxtDate=get-date -f "ddMMyyyHHmmss"
Write-Host "Generating HTML report"
$objHost= $env:COMPUTERNAME
$objHTML=$null
#Start of HTML Document format
    $objHTML=	"<html>"
    $objHTML+=	"<head>"
    $objHTML+=	"<Title><h1>" + $objHost + "</h1></Title>"
    $objHTML+=	"<Style>"
    $objHTML+=	" table{  border: 1px solid black;}`
			td {  border-bottom: 1px solid #ddd;text-align: left;font-size:12}`
			.label {  border-bottom: 1px solid #ddd;text-align: left;font-weight: bold;color:blue;font-size:18}`
			th {  border-bottom: 1px solid #ddd;text-align: left;font-size:15}`
"
    $objHTML+=	"</Style>"
    $objHTML+=	"</head>"
    $objHTML+=	"<body>"
    $objHTML+=	"<h1><b>"+ $objHost+"_"+$objFormattedDate+"</h1></b><th>"

#############System Info Table #################
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> SystemInfo  </th>"
    $objHTML+= "</tr>"
    ################Filling SystemInfo Table#######################
    $objHTML+=	"<tr><td><b> Operation System </b></td>"
    $objHTML+=	"<td>" + $SystemConfig["OS"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Hardware </b></td>"
    $objHTML+=	"<td>" + $SystemConfig["Model"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Install Date </b></td>"
    $objHTML+=	"<td>" + $SystemConfig["InstallDate"] + "</td></tr>"

    $objHTML+=	"<tr><td><b> OS Language </b></td>"
    $objHTML+=	"<td>" + $SystemConfig["Language"] + "</td></tr>"


    $objHTML+=	"<tr><td><b> Build Number </b></td>"
    $objHTML+=	"<td>" + $SystemConfig["Build"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> RAM </b></td>"
    $objHTML+=	"<td>" + $SystemConfig["PhysicalMemory"] + "GB</td></tr>"
    $objHTML+=	"<tr><td><b> CPU </b></td>"
    $objHTML+=	"<td>" + $SystemConfig["CPUInfo"] + "GB</td></tr>"
    $objHTML+=	"<tr><td><b> Last boot time </b></td>"
    $objHTML+=	"<td>" + $SystemConfig["LastBoot"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Uptime [days] </b></td>"
    $objHTML+=	"<td>" + $SystemConfig["Uptime"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> SCCM agent  </b></td>"
    $objHTML+=	"<td>" + $sccmstate + "</td></tr>"
    $objHTML+=	"<tr><td><b> BSA agent  </b></td>"
    $objHTML+=	"<td>" + $bsastate + "</td></tr>"
    $objHTML+=	"</table>"

# JAC
#########DOMAIN OR WORKGROUP###########
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Domain / Workgroup  </th>"
    $objHTML+= "</tr>"

    ################Filling domain/workgroup info Table#######################
    $objHTML+=	"<tr><td><b> Domain status</b></td>"
    $objHTML+=	"<td>" + $Domain["D1"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Domain FQDN </b></td>"
    $objHTML+=	"<td>" + $Domain["fqdn"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Workgroup status</b></td>"
    $objHTML+=	"<td>" + $Domain["W1"] + "</td></tr>"
    $objHTML+=	"</table>"

##################Computer AD groups################

    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Domain Groups  </th>"
    $objHTML+= "</tr>"
    foreach ($group in $pc){
        $namaste = $group.ToString().split(",")
        $objHTML+= "<tr><td>" + $namaste[0].substring(3) + "</td></tr>"
    }
    $objHTML+= "</table>"

#######firewall profiles status #########
    $objHTML+= "<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Windows Advanced Firewall profiles </th>"
    $objHTML+= "</tr>"
    $firewallhtml =""
    if($null -eq (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue))
    {
        $firewallhtml = '''<table>
        <colgroup><col/><col/></colgroup>
        <tr><th>name</th><th>Enabled</th></tr>'''
        foreach($Key in $firewall.Keys)
        {
            $firewallhtml += "<tr><td>" + $Key + "</td><td>" + $firewall[$Key] + "</td><tr>"
        }
        $firewallhtml+="</table>"
    }
    else 
    {
        $firewallhtml += Get-NetFirewallProfile | Select-Object name,enabled | ConvertTo-Html -Fragment | out-string
    }
    #Loop for each item in Array
	$objHTML+=	"<td>" + $firewallhtml + "</td>"
    $objHTML+=	"</table>"


###################Local Admins##########################
    $objHTML+= "<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> LocalAdministrators  </th>"
    $objHTML+= "</tr>"

    $objHTML+= "<tr>"
    $objHTML+= "<th><b> Domain  </b></th>"
    $objHTML+= "<th><b> Name  </b></th>"
    $objHTML+= "</tr>"
    foreach ($localadmin in $LocalAdmins){
        $AD = $LocalAdmin.Split("/")
        $objHTML+= "<tr>"
        $objHTML+=	"<td>" +		$AD[0]			+ "</td>"
        $objHTML+=	"<td>" +		$AD[1]			+ "</td>"
        $objHTML+= "</tr>"
    }


$objHTML+= "</table>"


###################Disk Space###########################
    #Set the Table and first header
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Disk Information  </th>"
    $objHTML+= "</tr>"

    #Set Headers
    $objHTML+= "<tr>"
    $objHTML+= "<th><b> Disk  </b></th>"
# $objHTML+= "<th><b> Description  </b></th>"
    $objHTML+= "<th><b> Size  </b></th>"
    $objHTML+= "<th><b> Available [GB] </b></th>"
    $objHTML+= "<th><b> Free space  </b></th>"
    $objHTML+= "</tr>"
    Foreach ( $objDisk in $objDiskInfo)
    {
	$objHTML+=	"<tr>"	    
        $Path = $objdisk.DeviceID + "\" | out-string
        $ACL = get-acl $Path.trim() | select-object accesstostring 
	#Dump information
	$objHTML+=	"<td>" +	$objDisk.DeviceID				 	+ "</td>"
	#   $objHTML+=	"<td>" +	$objDisk.VolumeName					+ "</td>"
	$objHTML+=	"<td>" +	[math]::Round($objDisk.Size/1024/1024/1024,2)		+ "GB</td>"
	$objHTML+=	"<td>" +	[math]::Round($objDisk.FreeSpace/1024/1024/1024,2)	+ "GB</td>"
    $objHTML+=	"<td>" +	[math]::Round(($objDisk.Freespace/$objDisk.Size)*100)	+ "%</td>"
	$objHTML+=	"</tr>"
    }
    $objHTML+=	"</table>"


#################Page File Settings#############################
    #Set the Table and first header
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Page File Settings </th>"
    $objHTML+= "</tr>"

    #Set Headers
    $objHTML+= "<tr>"
    $objHTML+= "<th><b> Name  </b></th>"
    $objHTML+= "<th><b> AllocatedBaseSize  </b></th>"
    $objHTML+= "<th><b> PeakUsage  </b></th>"

    foreach ($objPageFiles in $ObjPageFile)
    {
        $objHTML+=	"<tr>"
        $objHTML+=	"<td>" +	$objPageFile.Name		+ "</td>"
        $objHTML+=	"<td>" +	$objPageFile.AllocatedBaseSize	+ "</td>"
        $objHTML+=	"<td>" +	$objPageFile.PeakUsage	+ "</td>"
        $objHTML+=  "</tr>"
    }
    $objHTML+=	"</table>"

#########################EVENT VIEWER####################################



#ERRORS
    #Set the Table and first header
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Last 20 System Log Errors  </th>"
    $objHTML+= "</tr>"

    #Set Headers
    $objHTML+= "<tr>"
    $objHTML+= "<th><b> EventID  </b></th>"
    $objHTML+= "<th><b> InstanceID  </b></th>"
    $objHTML+= "<th><b> Time  </b></th>"
    $objHTML+= "<th><b> Source  </b></th>"
    $objHTML+= "<th><b> Message  </b></th>"
    $objHTML+= "</tr>"

#Loop for each item in Array
    Foreach ( $Errors in $EventError)
    {
        $objHTML+=	"<tr>"
        $objHTML+=	"<td>" +	$Errors.EventID		+ "</td>"
        $objHTML+=	"<td>" +	$Errors.InstanceID	+ "</td>"
        $objHTML+=	"<td>" +	$Errors.TimeGenerated			+ "</td>"
        $objHTML+=	"<td>" +	$Errors.Source		+ "</td>"
        $objHTML+=	"<td>" +	$Errors.Message		+ "</td>"
        $objHTML+=	"</tr>"

    }
    $objHTML+=	"</table>"
#STOPS
    #Set the Table and first header
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Last 5 Event Log Stops  </th>"
    $objHTML+= "</tr>"

    #Set Headers
    $objHTML+= "<tr>"
    $objHTML+= "<th><b> EventID  </b></th>"
    $objHTML+= "<th><b> InstanceID  </b></th>"
    $objHTML+= "<th><b> Time  </b></th>"
    $objHTML+= "<th><b> Source  </b></th>"
    $objHTML+= "<th><b> Message  </b></th>"
    $objHTML+= "</tr>"

    #Loop for each item in Array
Foreach ( $Stops in $eventStops)
    {
        $objHTML+=	"<tr>"
        $objHTML+=	"<td>" +	$Stops.EventID		+ "</td>"
        $objHTML+=	"<td>" +	$Stops.InstanceID	+ "</td>"
        $objHTML+=	"<td>" +	$Stops.TimeGenerated			+ "</td>"
        $objHTML+=	"<td>" +	$Stops.Source		+ "</td>"
        $objHTML+=	"<td>" +	$Stops.Message		+ "</td>"
        $objHTML+=	"</tr>"

    }
    $objHTML+=	"</table>"
#STARTS
    #Set the Table and first header
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Last 5 Event Log Starts  </th>"
    $objHTML+= "</tr>"

    #Set Headers
    $objHTML+= "<tr>"
    $objHTML+= "<th><b> EventID  </b></th>"
    $objHTML+= "<th><b> InstanceID  </b></th>"
    $objHTML+= "<th><b> Time  </b></th>"
    $objHTML+= "<th><b> Source  </b></th>"
    $objHTML+= "<th><b> Message  </b></th>"
    $objHTML+= "</tr>"

    #Loop for each item in Array
    Foreach ( $Start in $eventStarts)
    {
        $objHTML+=	"<tr>"
        $objHTML+=	"<td>" +	$Start.EventID		+ "</td>"
        $objHTML+=	"<td>" +	$Start.InstanceID	+ "</td>"
        $objHTML+=	"<td>" +	$Start.TimeGenerated			+ "</td>"
        $objHTML+=	"<td>" +	$Start.Source		+ "</td>"
        $objHTML+=	"<td>" +	$Start.Message		+ "</td>"
        $objHTML+=	"</tr>"
    }
    $objHTML+=	"</table>"

#RESTARTS TRIGGER
    #Set the Table and first header
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Last 5 Restart Triggers  </th>"
    $objHTML+= "</tr>"

    #Set Headers
    $objHTML+= "<tr>"
    $objHTML+= "<th><b> EventID  </b></th>"
    $objHTML+= "<th><b> InstanceID  </b></th>"
    $objHTML+= "<th><b> Time  </b></th>"
    $objHTML+= "<th><b> Source  </b></th>"
    $objHTML+= "<th><b> Message  </b></th>"
    $objHTML+= "</tr>"

    #Loop for each item in Array
    Foreach ( $Trigger in $RestartTrigger)
    {
        $objHTML+=	"<tr>"
        $objHTML+=	"<td>" +	$Trigger.EventID		+ "</td>"
        $objHTML+=	"<td>" +	$Trigger.InstanceID	+ "</td>"
        $objHTML+=	"<td>" +	$Trigger.TimeGenerated			+ "</td>"
        $objHTML+=	"<td>" +	$Trigger.Source		+ "</td>"
        $objHTML+=	"<td>" +	$Trigger.Message		+ "</td>"
        $objHTML+=	"</tr>"

    }
    $objHTML+=	"</table>"


#######################Filling Table Network####################################
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Network Configuration  </th>"
    $objHTML+= "</tr>"
    $objHTML+= $IPconf
<#
    $objHTML+=	"<tr><td><b> IP </b></td>"
    $objHTML+=	"<td>" + $IPconf["IP"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Subnet Mask </b></td>"
    $objHTML+=	"<td>" + $IPconf["Mask"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> DefaultGeteway </b></td>"
    $objHTML+=	"<td>" + $IPconf["Gateway"] + "</td></tr>"

    $objHTML+=	"<tr><td><b> DNS Name </b></td>"
    $objHTML+=	"<td>" + $IPconf["DNSName"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> DNS IP Addresses </b></td>"
    $objHTML+=	"<td>" + $IPconf["DNSIPS"] + "</td></tr>"

    $objHTML+=	"<tr><td><b> KMS Connection </b></td>"
    $objHTML+=	"<td>" + $IPconf["kms"] + "</td></tr>"
#>

    $objHTML+=	"</table>"

######################Filling Table Network Teaming####################################
    $TeamHTML = $Teaming | ConvertTo-Html -Fragment
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Network Teaming  </th>"
    $objHTML+= "</tr>"
    $objHTML+= "<tr><td>" + $TeamHTML + "</td></tr>"
#



$objHTML+=	"</table>"

##############Shares + ACL#################

    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Shared Folders  </th>"
    $objHTML+= "</tr>"
    #Set Headers
    $objHTML+= "<tr>"
    $objHTML+= "<th><b> Name  </b></th>"
    $objHTML+= "<th><b> ACL  </b></th>"
    $objHTML+= "</tr>"



#Loop for each item in Array
if($Shares.Length -gt 0)
{
    foreach ($Share in $Shares){
        if($Share.Path -eq "")
        {
            Continue
        }
        $ACL = get-acl -ErrorAction SilentlyContinue $Share.Path | select-object accesstostring
        $objHTML+=	"<tr>"
        $objHTML+=	"<td>" +	$Share.name	+ "</td>"
        $objHTML+=	"<td>" +	$ACL	+ "</td>"
        $objHTML+=	"</tr>"
    }
}



$objHTML+=	"</table>"

#############SCHD Tasks###################
$tasks = $schtasks | ConvertFrom-Csv | Select-Object TaskName,Author,Comment | Where-Object {
    ($_.TaskName -notmatch 'Microsoft') -and 
    ($_.Author -notmatch 'SYSTEM') -and 
    ($_.taskname -notmatch 'User_Feed_Synch') -and 
    ($_.Author -notmatch 'Microsoft Corporation') -and
    ($_.Author -notmatch 'Author') -and
    ($_.Author -notmatch 'Microsoft')}
    $objHTML+= "<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Task Scheduler </th>"
    $objHTML+= "</tr>"
    $taskhtml = $tasks | ConvertTo-Html -Fragment | out-string

    #Loop for each item in Array

    $objHTML+=	"<td>" + $taskhtml + "</td>"


    $objHTML+=	"</table>"


if( -not ($SystemConfig["vm"] -eq $True)){

#########GET ILO CONFIG###########
$IloInfo = Get-IloInfo

    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> iLo Info  </th>"
    $objHTML+= "</tr>"
    ################Filling ilo info Table#######################
    $objHTML+=	"<tr><td><b> Ilo IP </b></td>"
    $objHTML+=	"<td>" + $IloInfo["iloip"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Firmware </b></td>"
    $objHTML+=	"<td>" + $IloInfo["firmware"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Ilo Version </b></td>"
    $objHTML+=	"<td>" + $IloInfo["ver"] + "</td></tr>"
    $objHTML+=	"</table>"
}

    #########SEP TEST###########
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> SEP  </th>"
    $objHTML+= "</tr>"

    ################Filling SEP info Table#######################
    $objHTML+=	"<tr><td><b> Installed </b></td>"
    $objHTML+=	"<td>" + $sepout["Installed"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Status </b></td>"
    $objHTML+=	"<td>" + $sepout["Status"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Version </b></td>"
    $objHTML+=	"<td>" + $sepout["ver"] + "</td></tr>"
    $objHTML+=	"</table>"



    #########MC TEST###########
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> McAfee  </th>"
    $objHTML+= "</tr>"

    ################Filling SEP info Table#######################
    $objHTML+=	"<tr><td><b> Installed </b></td>"
    $objHTML+=	"<td>" + $mcout["Installed"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Status </b></td>"
    $objHTML+=	"<td>" + $mcout["Status"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Version </b></td>"
    $objHTML+=	"<td>" + $mcout["ver"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> AMCore version </b></td>"
    $objHTML+=	"<td>" + $mcout["AMCore"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> AMCore date </b></td>"
    $objHTML+=	"<td>" + $mcout["AMCoredate"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Installation path </b></td>"
    $objHTML+=	"<td>" + $mcout["Path"] + "</td></tr>"
    $objHTML+=	"</table>"

#########LICENCE AND ACTIVATION###########
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Licence and activation status  </th>"
    $objHTML+= "</tr>"

    ################Filling Licence and activation status table#######################
    $objHTML+=	"<tr><td><b> Licence status</b></td>"
    $objHTML+=	"<td>" + $Licence["status"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Licence channel </b></td>"
    $objHTML+=	"<td>" + $Licence["Channel"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Licence description </b></td>"
    $objHTML+=	"<td>" + $Licence["Description"] + "</td></tr>"
    $objHTML+=	"</table>"



#########Check SCCM###########
<#    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> SCCM Config  </th>"
    $objHTML+= "</tr>"

    ################Filling sccm info Table#######################
    $objHTML+=	"<tr><td><b> GUID </b></td>"
    $objHTML+=	"<td>" + $SCCMTest["LGUID"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> OK </b></td>"
    $objHTML+=	"<td>" + $SCCMTest["match"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Obsolete </b></td>"
    $objHTML+=	"<td>" + $SCCMTest["obsolete"] + "</td></tr>"
    $objHTML+=	"<tr><td><b> Client Version </b></td>"
    $objHTML+=	"<td>" + $SCCMTest["cver"] + "</td></tr>"


    $objHTML+=	"</table>"
#>
    ###################Port Check###########################
<#  #Set the Table and first header
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Ports Check  </th>"
    $objHTML+= "</tr>"

    #Set Headers
    $objHTML+= "<tr>"
    $objHTML+= "<th><b> Region  </b></th>"
    $objHTML+= "<th><b> Server name  </b></th>"
    $objHTML+= "<th><b> Port  </b></th>"
    $objHTML+= "<th><b> OK  </b></th>"
    $objHTML+= "</tr>"
    For ($i = 0;$i -lt $PortCheck[1].Length;$i++)
    {
	
		$objHTML+=	"<tr>"
	$objHTML+=	"<td>" + $PortCheck[1][$i]	+ "</td>"
	$objHTML+=	"<td>" + $PortCheck[2][$i]	+ "</td>"
	$objHTML+=	"<td>" + $PortCheck[3][$i]	+ "</td>"
	$objHTML+=	"<td>" + $PortCheck[4][$i]	+ "</td>"
	$objHTML+=	"</tr>"
    } 
    $objHTML+=	"</table>"
    #>
#######All services table#########
    $objHTML+= "<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Services [all] </th>"
    $objHTML+= "</tr>"
    $allserviceshtml = $all_services | ConvertTo-Html -Fragment | out-string
    #Loop for each item in Array
	$objHTML+=	"<td>" + $allserviceshtml + "</td>"
    $objHTML+=	"</table>"

######stopped services table######
    $objHTML+= "<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Services [starttype=automatic, state=stopped] </th>"
    $objHTML+= "</tr>"
    $stoppedserviceshtml = $stopped_services | ConvertTo-Html -Fragment | out-string

    #Loop for each item in Array
	$objHTML+=	"<td>" + $stoppedserviceshtml + "</td>"
    $objHTML+=	"</table>"



################HOT FIX###################
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Patches Installed  </th>"
    $objHTML+= "</tr>"
    #Set Headers
    $objHTML+= "<tr>"
    $objHTML+= "<th><b> HotFixID  </b></th>"
    $objHTML+= "<th><b> Date  </b></th>"
    $objHTML+= "<th><b> Installed By  </b></th>"
    $objHTML+= "</tr>"

    #Loop for each item in Array
    Foreach ( $HotFix in $FixHot)
    {
        $objHTML+=	"<tr>"
        $objHTML+=	"<td>" +	$HotFix.HotFixID	+ "</td>"
        $objHTML+=	"<td>" +	$HotFix.InstalledOn	+ "</td>"
        $objHTML+=	"<td>" +	$HotFix.InstalledBy	+ "</td>"
$objHTML+=	"</tr>"

    }
    $objHTML+=	"</table>"

#JAC Getting installed applications
    $objHTML+=	"<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Applications Installed  </th>"
    $objHTML+= "</tr>"
    #Set Headers
    $objHTML+= "<tr>"
    $objHTML+= "<th><b> Application name  </b></th>"
    $objHTML+= "<th><b> Version  </b></th>"
    $objHTML+= "<th><b> Install Date  </b></th>"
    $objHTML+= "</tr>"
    #Loop for each item in Array
    Foreach ( $app in $apps)
    {
        $objHTML+=	"<tr>"
        $objHTML+=	"<td>" +	$App.DisplayName	+ "</td>"
        $objHTML+=	"<td>" +	$App.DisplayVersion	+ "</td>"
        $objHTML+=	"<td>" +	$App.InstallDate	+ "</td>"
        $objHTML+=	"</tr>"
    }
    $objHTML+=	"</table>"
	
	###################Agents installed##########################
    $objHTML+= "<table width=100%>"
    $objHTML+= "<tr> <br> </tr>" 
    $objHTML+= "<tr>"
    $objHTML+= "<th class=""label""> Agents installed   </th>"
    $objHTML+= "</tr>"

    $objHTML+= "<tr>"
    $objHTML+= "<th><b> Agent name  </b></th>"
    $objHTML+= "<th><b> Version  </b></th>"
	$objHTML+= "<th><b> Latest version  </b></th>"
    $objHTML+= "</tr>"
	$services=@("ase","nagios-client-nacl","nsrexecd","RSCDsvc","healthservice","CSFalconService")
	foreach ($service in $services){
    
        try {
            $get = Get-WmiObject -Class Win32_Service | Where-Object {$_.name  -Like "$service"} | Select-Object Name, Displayname, Pathname 
            $pathname= $Get.Pathname -replace ' -k.*', ''   

            $pathname= $pathname -replace '\"', ''   
            $pathname= $pathname -replace ' -WIN.*', ''   
            $version=(Get-Item $pathname).versioninfo.fileversion
            if ($service -eq "ase"){
            $latestversion="1.7.44.0"
            }

            if ($service -eq "nagios-client-nacl"){
            $latestversion="v2.1.1 build 28"
            }

            if ($service -eq "nsrexecd"){
            $latestversion="18.2.0.3.Build.168"
            }

            if ($service -eq "RSCDsvc"){
            $latestversion="8.9.04.0"
            }

            if ($service -eq "healthservice"){
            $latestversion="7.1.10184.0"
            }

            if ($service -eq "CSFalconService"){
            $latestversion="5.23.10504.0"
            }

            if ($version -eq $latestversion){
            $colorversion='style="background-color:#00f500"'
            }

            else
            {
            $colorversion='style="background-color:#ffffff"'
            }

            $objHTML+= "<tr>"
                    $objHTML+=	"<td>" +		$get.displayname			+ "</td>"
                    $objHTML+=	'<td '+ $colorversion+' >' +		$version			+ "</td>"
                    $objHTML+=	"<td>" +		$latestversion			+ "</td>"
                    $objHTML+= "</tr>"
        }  
        catch {}
                
}


$objHTML+= "</table>"

	###################Tooling details installed##########################
    $objHTML+= "<table width=100%>"
    $objHTML+= '<tr> <br> </tr>' 
    $objHTML+= "<tr>"
    $objHTML+= '<th class="label"> Atos Tooling Details  </th>'
    $objHTML+= "</tr>"

    $objHTML+= "<tr>"
    $objHTML+= '<th><b> Agent name  </b></th>'
    $objHTML+= '<th><b> Current Version  </b></th>'
	$objHTML+= '<th><b> Service Status  </b></th>'
    $objHTML+= '<th><b> BSA User  </b></th>'
    $objHTML+= '<th><b> Agent Home </b></th>'
    $objHTML+= '<th><b> EPO Server List </b></th>'
    $objHTML+= '<th><b> EPO Last Used </b></th>'
    $objHTML+= '<th><b> EPO Version </b></th>'
    $objHTML+= '<th><b> EPO Last Update </b></th>'
    $objHTML+= '</tr>'
    ###################BSA##########################
    if($tooling.ContainsKey('BSA'))
    {
        $objHTML+= "<tr>"
        $objHTML+=	"<td>BSA</td>"
        $objHTML+=	"<td>"+		    $tooling['BSA'].InstalledVersion			+ "</td>"
        $objHTML+=	"<td>" +		$tooling['BSA'].Status		+ "</td>"
        $objHTML+=	"<td>" +		$tooling['BSA'].BSA_User		+ "</td>"
        $objHTML+=	"<td>" +		$tooling['BSA'].Agent_Home		+ "</td>"
        $objHTML+=  "<td></td><td></td><td></td><td></td>"
        $objHTML+= "</tr>"
    }
    if($tooling.ContainsKey('EPO'))
    {
        $objHTML+= "<tr>"
        $objHTML+=	"<td>EPO</td>"
        $objHTML+=	"<td>"+		    $tooling['EPO'].AgentVersion			+ "</td>"
		$objHTML+=	"<td>" +		$tooling['EPO'].Status		+ "</td>"
        $objHTML+=	"<td></td>"
        $objHTML+=	"<td>" +		$tooling['EPO'].AgentHome		+ "</td>"
        $objHTML+=  "<td>"+         $tooling['EPO'].ServerList +"</td>"
        $objHTML+=  "<td>" +        $tooling['EPO'].LastUsed + "</td>"
        $objHTML+=  "<td>" +        $tooling['EPO'].EPOVersion +"</td>"
        $objHTML+=  "<td>" +        $tooling['EPO'].LastPolicyUpdate + "</td>"
        $objHTML+= "</tr>"
    }
    if($tooling.ContainsKey('Centreon'))
    {
        $objHTML+= "<tr>"
        $objHTML+=	"<td>Centreon</td>"
        $objHTML+=	"<td>"+		    $tooling['Centreon'].AgentVersion			+ "</td>"
		$objHTML+=	"<td>" +		$tooling['Centreon'].Service		+ "</td>"
        $objHTML+=	"<td></td>"
        $objHTML+=	"<td>" +		$tooling['Centreon'].AgentHome		+ "</td>"
        $objHTML+=  "<td></td><td></td><td></td><td></td>"
        $objHTML+= "</tr>"
    }
    if($tooling.ContainsKey('Flexera'))
    {
        $objHTML+= "<tr>"
        $objHTML+=	"<td>Flexera</td>"
        $objHTML+=	"<td>"+		    $tooling['Flexera'].AgentVersion			+ "</td>"
		$objHTML+=	"<td>" +		$tooling['Flexera'].Service		+ "</td>"
        $objHTML+=	"<td></td>"
        $objHTML+=	"<td>" +		$tooling['Flexera'].Agent_Home		+ "</td>"
        $objHTML+=  "<td></td><td></td><td></td><td></td>"
        $objHTML+= "</tr>"
    }
$objHTML+='</table>"'
Get-ChildItem
#End Of HTML
$interval = New-TimeSpan -Start $startTime -End (Get-Date)
$objHtml+= "<i> Report generated in {0}m {1}s</i>" -f $interval.Minutes, $interval.Seconds
$objHTML+=	"</body>"
$objHTML+=	"</html>"



#$objHTML | out-file "\\155.45.163.189\ts_emea$\_public\a562569\$env:COMPUTERNAME.html"
#$objHTML | out-file ".\$env:COMPUTERNAME.html"


# filename + timestamp prevenets owerwrite output file (mala rzecz a cieszy)
$filename = "$env:COMPUTERNAME {0:yyyyMMdd-HHmm}" -f (Get-Date)
$objHTML | out-file .\$filename.html
