param(
	[Parameter(Mandatory = $true)]
	[Alias("VM Name")]
	[string]$hostName,

	[Parameter(Mandatory = $true)]
	[ValidateSet("vm1", "vm2", "vm3", "vm4", "vm1.egobranenet.com", "vm2.egobranenet.com", "vm3.aad.egobrane.com", "vm4.aad.egobrane.com")]
	[string]$targetHost,

	[Parameter(Mandatory = $true)]
	[ValidateSet(1, 2)]
	[int]$generation = 1,

	[Parameter()]
	[ValidateSet("LAN - Virtual Network", "Private - Virtual Network", "WAN - Virtual Network")]
	[string]$switchName = "LAN - Virtual Network",

	[Parameter(Mandatory = $true)]
	[ValidatePattern("^(Windows|Server)*[\WServer0-9]*")]
	[string]$operatingSystem,
	[int]$CPUCount = 4,
	[int64]$minMemory = 2048MB,
	[int64]$maxMemory = 4096MB,
	[string]$sourceImage,
	[int]$VLAN
)

if ($targetHost.Length -eq 3)
{
	if ($targetHost -match "vm[1-2]")
	{
		$targetHost += ".egobranenet.com"
	}
	elseif ($targetHost -match "vm[3-4]")
	{
		$targetHost += ".aad.egobrane.com"
	}
}

if ([string]::IsNullOrEmpty($sourceImage))
{
	if ($operatingSystem -match "^(Windows Server|Server)$")
	{
		do
		{
			$osVersion = Read-Host "Windows Server selected. Which year? Eg. 2016, 2019, 2022"
		} until ($osVersion -match "^(2016|2019|2022|16|19|22)$")
		$osVersion = $osVersion.SubString($osVersion.Length - 2)
	}
	elseif ($operatingSystem -match "^Windows Server\s(2016|2019|2022|16|19|22)$")
	{
		$osVersion = $operatingSystem.Substring($operatingSystem.Length - 2)
	}
	elseif ($operatingSystem -match "^Windows$")
	{
		do
		{
			$osVersion = Read-Host "Microsoft Windows selected. Which version? 10 or 11"
		} until ($osVersion -match "^(10|11)$")
		$osVersion = $osVersion.SubString($osVersion.Length - 2)
	}
	elseif ($operatingSystem -match "^Windows\s(10|11)$")
	{
		$osVersion = $operatingSystem.Substring($operatingSystem.Length - 2)
	}
	else
	{
		Return "Operating system not valid. Exiting script."
	}

	switch ($osVersion)
	{
		"10"
		{
			if ($generation -eq 1)
			{
				$sourceImage = "Win10_Ent_x64_VL_Clean"
			}
			elseif ($generation -eq 2)
			{
				Return "No gen 2 image exists for Windows 10."
			}
		}

		"16"
		{
			if ($generation -eq 1)
			{
				$sourceImage = "Win2k16_x64_Clean"
			}
			elseif ($generation -eq 2)
			{
				Return "No gen 2 image exists for Windows Server 2016."
			}
		}

		"19"
		{
			do
			{
				$license = Read-Host "VL image? y/n"
			} until ($license -match "^[yn]$")
			if ($license -eq "y")
			{
				if ($generation -eq 2)
				{
					$sourceImage = "Win2k19_x64_Clean_VL_G2"
				}
				elseif ($generation -eq 1)
				{
					$sourceImage = "Win2k19_x64_Clean_VL"
				}
			}
			elseif ($license -eq "n")
			{
				$sourceImage = "Win2k19_x64_Clean"
				if ($generation -eq 2)
				{
					Return "There is no non-VL gen 2 image for Windows Server 2019."
				}
			}
		}

		"22"
		{
			do
			{
				$license = Read-Host "VL image? y/n"
			} until ($license -match "^[yn]$")
			if ($license -eq "y")
			{
				if ($generation -eq 2)
				{
					$sourceImage = "Win2k22_x64_Clean_VL_G2"
				}
				elseif ($generation -eq 1)
				{
					$sourceImage = "Win2k22_x64_Clean_VL"
				}
			}
			elseif ($license -eq "n")
			{
				$sourceImage = "Win2k22_x64_Clean"
				if ($generation -eq 2)
				{
					Return "There is no non-VL gen 2 image for Windows Server 2022."
				}
			}
		}

		"11"
		{
			Return "No image to copy exists for Windows 11 at this time."
		}
	}
}

$hyperVPath = "\\$targetHost\c`$\SAN\SSD_Mirror\Hyper-V"
$destinationPath = Join-Path $hyperVPath $hostName
$destinationVHDPath = Join-Path $destinationPath "Virtual Hard Disks"
Write-Host "Target host is $targetHost, creating $hostName at $destinationPath"

New-VM -Name $hostName -ComputerName $targetHost -NoVHD -Path $hyperVPath -Generation $generation -SwitchName $switchName
Set-VMMemory -VMName $hostName -ComputerName $targetHost -DynamicMemoryEnabled $true -MinimumBytes $minMemory -StartupBytes $minMemory -MaximumBytes $maxMemory
Set-VMProcessor -VMName $hostName -ComputerName $targetHost -Count $CPUCount

$disabledIntegrationServices = @((Get-VMIntegrationService -VMName $hostName -ComputerName $targetHost | Where-Object { $_.Enabled -eq $false }).Name)
foreach ($integrationService in $disabledIntegrationServices)
{
	Enable-VMIntegrationService -VMName $hostName -ComputerName $targetHost -Name $integrationService
}

$s = New-PSSession -Name $targetHost -ComputerName $targetHost
Invoke-Command -Session $s -ScriptBlock {
	$vmSID = (Get-VM -VMName $using:hostName).VMId.Guid;
	$acl = Get-Acl -Path $using:destinationPath;
	$permission = $vmSID, 'Read,Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow';
	$rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permission;
	$acl.AddAccessRule($rule);
	$acl | Set-Acl -Path $using:destinationPath;
}
Remove-PSSession $s

Start-VM -VMName $hostName -ComputerName $targetHost
do
{
	Write-Host "Waiting for MAC address..."
	Start-Sleep -Seconds 2
} until ((Get-VMNetworkAdapter -VMName $hostName -ComputerName $targetHost).MacAddress -ne "000000000000")

Stop-VM -VMName $hostName -ComputerName $targetHost -Force
do
{
	Write-Host "Retrieving static MAC address..."
	Start-Sleep -Seconds 3
} until ((Get-VM -VMName $hostName -ComputerName $targetHost).State -eq "Off")

Set-VMNetworkAdapter -VMName $hostName -ComputerName $targetHost -StaticMacAddress $(Get-VMNetworkAdapter -VMName $hostName -ComputerName $targetHost).MacAddress
if (![string]::IsNullOrEmpty($VLAN))
{
	Set-VMNetworkAdapterVlan -VMName $hostName -ComputerName $targetHost -Access -VlanId $VLAN
}
Write-Host "Copying virtual hard disk..."

robocopy /mt /z "\\vm1\c`$\SAN\SSD_Mirror\VMLibrary\VHDs\$sourceImage" $destinationVHDPath *.*

$VHDPath = Join-Path $destinationVHDPath (Get-ChildItem $destinationVHDPath).Name
if ($generation -eq 1)
{
	Add-VMHardDiskDrive -VMName $hostName -ComputerName $targetHost -Path $VHDPath -ControllerType IDE
	Set-VMBios -VMName $hostName -ComputerName $targetHost -StartupOrder IDE, CD, LegacyNetworkAdapter, Floppy
}
elseif ($generation -eq 2)
{
	Add-VMHardDiskDrive -VMName $hostName -ComputerName $targetHost -Path $VHDPath -ControllerType SCSI
	Set-VMFirmware -VMName $hostName -ComputerName $targetHost -FirstBootDevice $(Get-VMHardDiskDrive -VMName $hostName -ComputerName $targetHost)
}

$prompt = Read-Host "VM $hostName created. Would you like to start it? y/n"
if ($prompt -eq "y")
{
	Start-VM -VMName $hostName -ComputerName $targetHost
	Write-Host "VM $hostName creation complete."
}
else
{
	Write-Host "VM $hostName creation complete."
}