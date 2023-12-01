$dsoRoot = 'C:\egobrane\$DevSecOps'
$duoPath = Join-Path $dsoRoot "duo-installer.exe"
$azCopyPath = Join-Path $dsoRoot "azcopy.exe"
$dsoStorageRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/Resources"
$result = (& $azCopyPath copy "$dsoStorageRoot/duo-win-login-4.2.0.exe" `
		$duoPath --output-level="essential") | Out-String
if($LASTEXITCODE -ne 0)
{
	throw (("Copy error. $result"))
}
(& $duoPath /S /V`" /qn IKEY="" SKEY="" HOST="" AUTOPUSH="#1" FAILOPEN="#0" RDPONLY="#0" UAC_PROTECTMODE="#2"`")