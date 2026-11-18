# Show XEN/Citrix  devices
$env:devmgr_show_nonpresent_devices = 1
Write-Host "Searching for Xen/Citrix  devices..." -ForegroundColor Yellow
# Get non-present Xen devices
$Devices = Get-PnpDevice |
    Where-Object {
        $_.FriendlyName -match "Xen|Citrix" -or
        $_.InstanceId -match "XEN"
    }
if (-not $Devices) {
    Write-Host "No Xen devices found." -ForegroundColor Green
    exit
}
$Devices | Format-Table Status, Class, FriendlyName, InstanceId -AutoSize
