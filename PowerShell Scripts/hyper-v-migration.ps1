param(
	[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
	[Alias("VMName")]
	[string[]]$hostNames = -Split $hostNames,

	[Alias("Target")]
	[ValidateSet("vm3.aad.egobrane.com", "vm4.aad.egobrane.com")]
	[string]$targetHost
)

#Target Host Selection
$targetHost = Read-Host -Prompt "Please enter target host FQDN. eg. vm3.aad.egobrane.com or vm4.aad.egobrane.com"
if (($targetHost -eq 'vm3.aad.egobrane.com') -or ($targetHost -eq 'vm4.aad.egobrane.com'))
{
	Write-Host "Target Host set to $targetHost"
}
else
{
	Write-Host "Target Host not valid. Please enter vm3.aad.egobrane.com or vm4.aad.egobrane.com"
	Break
}

#Grab Credentials for egobraneCOM portions
$egobranecomCredential = Get-Credential
$egobranecomUsername = $egobranecomCredential.UserName
net use "\\$targetHost\c$" /user:$egobranecomUsername


foreach ($hostName in $hostNames) {

	$destinationPath = "\\$targetHost\c`$\ClusterStorage\SSD_Mirror\Hyper-V\$hostName"
	if([string]::IsNullOrEmpty($hostName)) {throw "Hostname blank."}

	Write-Host "Detecting source host..."
	if (((Get-VM -ComputerName vm1 | Where-Object {$_.Name -eq $hostName}).Name | Out-String -Stream) -eq $hostName)
	{
		$sourceHost = "vm1"
	}
	elseif (((Get-VM -ComputerName vm2 | Where-Object {$_.Name -eq $hostName}).Name | Out-String -Stream) -eq $hostName)
	{
		$sourceHost = "vm2"
	}
	else {
		Write-Host "VM cannot be found."
		Break
	}

	Write-Host "Source host detected as $sourceHost."
	Write-Host "Clearing out clustering data..."
	Remove-ClusterResource -Cluster vm -Name "Virtual Machine Configuration $hostName"

	Write-Host "Exporting $hostName..."
	Export-VM -ComputerName $sourceHost -Name $hostName -Path "\\$sourceHost\c`$\ClusterStorage\SSD_Mirror\Exports"

	Write-Host "Copying $hostName export to new location..."
	robocopy /mt /z /move /s "\\$sourceHost\c`$\ClusterStorage\SSD_Mirror\Exports\$hostName" $destinationPath

	Write-Host "Verifying export..."
	$configType = (Get-ChildItem -Path "$destinationPath\Virtual Machines\" | Out-String -Stream)
	if ($configType -like '*xml*')
	{
		$importFile = (Get-ChildItem -Path "$destinationPath\Virtual Machines\*.xml").Name
		Write-Host "XML configuration detected at $importFile"
	}
	elseif ($configType -like '*vmcx*')
	{
		$importFile = (Get-ChildItem -Path "$destinationPath\Virtual Machines\*.vmcx").Name
		Write-Host "VMCX configuration detected at $importFile"
	}
	else
	{
		Read-Host -Prompt "Configuration File not found. Please verify source and destination folders for its presence."
	}

	$importPath = Join-Path "$destinationPath\Virtual Machines\" $importFile
	Write-Host "Import Path is $importPath"

	Write-Host "Importing $hostName to $targetHost..."
	$s = New-PSSession -Name $targetHost -ComputerName $targetHost -Credential $egobranecomCredential
	Invoke-Command -Session $s -ScriptBlock {
		Import-VM -Computername $using:targetHost -Path $using:importPath;
		$vmSID = (Get-VM $using:hostName).VMId.Guid;
		$acl = Get-Acl -Path "\\$using:targetHost\c$\ClusterStorage\SSD_Mirror\Hyper-V\$using:hostName";
		$permission = $vmSID, 'Read,Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow';
		$rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permission;
		$acl.AddAccessRule($rule);
		$acl | Set-Acl -Path "\\$using:targetHost\c$\ClusterStorage\SSD_Mirror\Hyper-V\$using:hostName"
	}

	Write-Host "VM has been copied over and imported. Please verify next message, as remainder of script will destroy the old VM."
	Read-Host -Prompt "Please verify that VM $hostName can be started on $targetHost and enter any key to continue"

	Write-Host "Stopping VM..."
	Stop-VM -ComputerName $sourceHost -Name $hostName
	Write-Host "Removing Snapshots..."
	Get-VM -ComputerName $sourceHost | Where-Object {$_.Name -eq $hostName} | Remove-VMSnapshot
	Write-Host "Deleting VM..."
	Get-VM -ComputerName $sourceHost | Where-Object {$_.Name -eq $hostName} | Remove-VM -Force

	Write-Host "Freeing up old VM storage..."
	$sourceVMPath = Join-Path "\\$sourceHost\c$\ClusterStorage\SSD_Mirror\Hyper-V\" $hostName
	if(Test-Path $sourceVMPath)
	{
		Remove-Item -Path $sourceVMPath -Recurse -Force -Confirm:$true
	} else {Write-Host "Cannot find $hostName storage."}

	Write-Host "$hostName migrated."
}

#Clean up
net use "\\$targetHost\c$" /D
Remove-PSSession $s