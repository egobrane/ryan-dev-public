# This script downloads and sets the index.htm for an IIS server based on expected values
$azCopyPath = "C:\Temp\azcopy.exe"
$dsoStorageRoot = "https://egobrane.blob.core.usgovcloudapi.net/cyberops/"


$indexPath = "C:\inetpub\wwwroot\index.htm"
Get-ChildItem "C:\inetpub\wwwroot\" -Exclude "web.config" | Remove-Item -Force -Confirm -ErrorAction SilentlyContinue
$result = (& $azCopyPath copy "$dsoStorageRoot/Redirects/testindex.htm" `
		$indexPath --overwrite=true --output-level="essential") | Out-String
if($LASTEXITCODE -ne 0)
{
	throw (("Copy error. $result"))
}

# This script tests to make sure the testindex.htm is the expected file, for use in automation

$indexPath = "C:\inetpub\wwwroot\index.htm"
if ((Test-Path -Path $indexPath) -and ((Get-Content -Path $indexPath |
			Out-String -Stream) -like "*./egobrane*"))
{
	$true
}
else
{
	$false
}