# This script downloads LGPO from Azure Storage and a combined .PolicyRules file generated from PolicyAnalyzer and applies it to the local machine
# works to propagate GPOs on disparate hosts with no domain membership or visibility to a DC
# compliance can be measured and ensured in Azure Automation with DSC

param (
	[Parameter(Mandatory=$true)]
	[string]$azureStorageUrl = "https://egobrane.blob.core.usgovcloudapi.net/cyberops/",
	
	[Parameter(Mandatory=$true)]
	[string]$localStorageRoot = "C:\Temp",

	[Parameter(Mandatory=$true)]
	[string]$gpoType = "DefaultDomainPolicy",

	[Parameter(Mandatory=$true)]
	[string]$azCopyPath = "C:\Temp\azcopy.exe"
)


$lgpoPath = Join-Path $localStorageRoot "\Tools\LGPO.exe"
$gpoPath = Join-Path $localStorageRoot "\Group Policy\$gpoType.PolicyRules"

$result = (& $azCopyPath copy "$azureStorageUrl/Tools/LGPO.exe" `
		$lgpoPath --overwrite=ifSourceNewer --output-level="essential") | Out-String
if($LASTEXITCODE -ne 0)
{
	throw (("Copy error. $result"))
}

$result = (& $azCopyPath copy "$azureStorageUrl/Group Policy/$gpoType.PolicyRules" `
		$gpoPath --overwrite=ifSourceNewer --output-level="essential") | Out-String
if($LASTEXITCODE -ne 0)
{
	throw (("Copy error. $result"))
}

(& $lgpoPath /q /p $gpoPath)