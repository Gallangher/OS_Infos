#################################################################################
#list info of multiple OneView in one table
#$ovlist - list of all available OneView servers
#
#################################################################################
# Connect-OVMgmt -Hostname 10.41.2.10 -UserName Administrator -password  22222
# Connect-OVMgmt -Hostname 10.41.2.31 -UserName Administrator -password  11111

$ovlist=("encl-com-p101","encl-com-p104","encl-com-p301","encl-com-p304","10.41.2.10","10.41.2.31")
$cred=Get-Credential -UserName ReadOnlyUserName -Message "OneView pass: ReadOnlyAccountPass"
$conn=@{}
$total_server=@()
$total_ic=@()
$total_enc=@()
#disconnect existing connections to ov
for($i=1; $i -le $ovlist.Length; $i++){
    try
    {
        $x=Disconnect-OVMgmt -ApplianceConnection $i -InformationAction SilentlyContinue
    } catch{
        Write-Host "No connection $i"
    }
}
clear
#get all info
foreach($ov in $ovlist){
    try {
        $conn[$ov]=Connect-OVMgmt -Hostname "$ov" -credential $cred -InformationAction SilentlyContinue
        $total_server += Get-OVServer -ApplianceConnection $conn[$ov] -InformationAction SilentlyContinue
        $total_ic += Get-OVInterconnect -ApplianceConnection $conn[$ov] -InformationAction SilentlyContinue
        $total_enc += Get-OVEnclosure -ApplianceConnection $conn[$ov] -InformationAction SilentlyContinue
    }catch{
               Write-Host "No connection :( to $ov"
    }
}
$total_server | Out-GridView
$total_ic | Out-GridView
$total_enc | Out-GridView
disconnect existing connections to ov on finish
for($i=1; $i -le $ovlist.Length; $i++){
    try
    {
        $x=Disconnect-OVMgmt -ApplianceConnection $i -InformationAction SilentlyContinue
    } catch{
        Write-Host "No connection $i"
    }
}
