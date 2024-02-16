# This script sets registry keys on all user profiles and default keys that force Windows to show file extensions and hidden folders

Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt -Name "DefaultValue" -Value 0 -Force -ErrorAction SilentlyContinue
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$profileSIDs = @((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.ProfileImagePath -like "C:\Users\*" -and $_.ProfileImagePath -notlike "C:\Users\default*"}).PSChildName)
foreach ($profileSID in $profileSIDs)
{
	$profilePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$profileSID").ProfileImagePath
	if (Get-ChildItem "HKU:\$profileSID" -ErrorAction SilentlyContinue)
	{
		$profileLoaded = $true
		$userKeyPath = "HKU:\$profileSID"
	}
	elseif (Test-Path "$profilePath\NTUSER.DAT" -ErrorAction SilentlyContinue)
	{
		$profileLoaded = $false
		$userKeyPath = "HKLM:\TempHive_$profileSID"
		& reg.exe load "HKLM\TempHive_$profileSID" "$profilePath\NTUSER.DAT"
	}
	else
	{
		Write-Host "Profile path does not exist, skipping user."
		Continue
	}
	Set-ItemProperty -Path $userKeyPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "Hidden" -Value 1 -Force -ErrorAction SilentlyContinue
	Set-ItemProperty -Path $userKeyPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "HideFileExt" -Value 0 -Force -ErrorAction SilentlyContinue

	if (!$profileLoaded)
	{
		& reg.exe unload "HKLM\TempHive_$profileSID"
	}
}
Remove-PSDrive -Name HKU

# This script just tests to make sure that settings are set as expected
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$profileSIDs = @((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.ProfileImagePath -like "C:\Users\*" -and $_.ProfileImagePath -notlike "C:\Users\default*"}).PSChildName)
foreach ($profileSID in $profileSIDs)
{
	$profilePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$profileSID").ProfileImagePath
	if (Get-ChildItem "HKU:\$profileSID" -ErrorAction SilentlyContinue)
	{
		$profileLoaded = $true
		$userKeyPath = "HKU:\$profileSID"
	}
	elseif (Test-Path "$profilePath\NTUSER.DAT" -ErrorAction SilentlyContinue)
	{
		$profileLoaded = $false
		$userKeyPath = "HKLM:\TempHive_$profileSID"
		& reg.exe load "HKLM\TempHive_$profileSID" "$profilePath\NTUSER.DAT"
	}
	else
	{
		Write-Host "Profile path does not exist, skipping user"
		Continue
	}
	[System.Collections.ArrayList]$hiddenFilesValues = @(($hiddenFilesValues) + ((Get-ItemProperty -Path $userKeyPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -ErrorAction SilentlyContinue).Hidden))
	[System.Collections.ArrayList]$fileExtensionsValues = @(($fileExtensionsValues) + ((Get-ItemProperty -Path $userKeyPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -ErrorAction SilentlyContinue).HideFileExt))
				
	if (!$profileLoaded)
	{
		& reg.exe unload "HKLM\TempHive_$profileSID"
	}
}
Remove-PSDrive -Name HKU
[System.Collections.ArrayList]$fileExtensionsValues = @(($fileExtensionsValues) + ((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt -ErrorAction SilentlyContinue).DefaultValue))
$hiddenFilesValue = $hiddenFilesValues | Get-Unique
$fileExtensionsValue = $fileExtensionsValues | Get-Unique
if(!($hiddenFilesValue -eq "0", "2") -and !($fileExtensionsValue -eq "1"))
{
	$true
}
else
{
	$false
}