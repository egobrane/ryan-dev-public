# This script licenses Windows Server regardless of OS version

param (
	[Parameter(Mandatory=$true)]
	[string]$productKey2016 = "flkdsjaflkasdjdflkj",

	[Parameter(Mandatory=$true)]
	[string]$productKey2022 = "asldikfjalsdkjfklja"
)


$operatingSystem = (Get-ComputerInfo).OsName
if ($operatingSystem -like "*2016*")
{
	$productKey = $productKey2016
}
elseif ($operatingSystem -like "*2022*")
{
	$productKey = $productKey2022
}
else
{
	Write-Host "Operating System type invalid for this script. Required: Server 2016 or 2022"
}
$sLmgr = 'C:\Windows\System32\slmgr.vbs'
$cScript = 'C:\Windows\System32\cscript.exe'
Start-Process -FilePath $cScript -ArgumentList ($sLmgr, '-ipk', $productKey) | Out-Null
Start-Process -FilePath $cScript -ArgumentList ($sLmgr, '-ato')



# This portion checks if the current key matches the expected values

$operatingSystem = (Get-ComputerInfo).OsName
if ($operatingSystem -like "*2016*")
{
	$productKeyExpression = $productKey2016
}
elseif ($operatingSystem -like "*2022*")
{
	$productKeyExpression = $productKey2022
}
else
{
	Write-Host "Operating System type invalid for this script. Required: Server 2016 or 2022"
}
$partialProductKey = $productKeyExpression.SubString($productKeyExpression.length - 5, 5)
if ((Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object { $_.PartialProductKey -ne $null } |
		Select-Object -Property PartialProductKey).PartialProductKey -contains $partialProductKey)
{
	$true
}
else
{
	$false
}