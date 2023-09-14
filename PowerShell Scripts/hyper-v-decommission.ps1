$HostNames = @(
    'hostname',
	'other-hostname'
)

foreach ($HostName in $HostNames) {
    $VMHost = $HostName
    $hypervStorage = "\\vm1\c$\ClusterStorage\SSD_Mirror\Hyper-V\"
    $vmPath = Join-Path $hypervStorage $VMHost

    if([string]::IsNullOrEmpty($HostName)) {throw "HostName Blank."}
    if($vmPath -eq $hypervStorage) {throw "Invalid vmPath."}

    Stop-VM -ComputerName vm1,vm2 -Name $VMHost 
    Get-VM -ComputerName vm1,vm2 | Where-Object {$_.Name -eq $VMHost} | Remove-VMSnapshot

    Remove-ClusterResource -Cluster vm -Name "Virtual Machine Configuration $VMHost" -Force

    Get-VM -ComputerName vm1,vm2 | Where-Object {$_.Name -eq $VMHost} | Remove-VM -Force

    if(Test-Path $vmPath)
    {
        Remove-Item -Path $vmPath -Recurse -Force -Confirm:$true
    } else {Write-Host "Cannot find $($HostName) storage."}

}


# Create new VM
robocopy /mt /z "C:\ClusterStorage\SSD_Mirror\VMLibrary\VHDs\[Template Folder]" `
"C:\ClusterStorage\SSD_Mirror\Hyper-V\[VM Name]\Virtual Hard Disks" *.*