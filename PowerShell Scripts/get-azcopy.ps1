# This script downloads the latest version of AzCopy from Microsoft

param (
	[Parameter(Mandatory=$true)]
	[string]$targetFolder = ""
)

$ProgressPreference = "SilentlyContinue"
$azCopyZipUrl = (Invoke-WebRequest -UseBasicParsing -Uri $using:azCopyDownloadUrl -MaximumRedirection 0 -ErrorAction SilentlyContinue).headers.location
$azCopyZipFile = Split-Path $azCopyZipUrl -Leaf
$azCopyZipPath = Join-Path $targetFolder $azCopyZipFile
$azCopyDir = Join-Path $targetFolder "azcopy"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri $azCopyZipUrl -OutFile $azCopyZipPath
Expand-Archive -Path $azCopyZipPath -DestinationPath $azCopyDir -Force
$ProgressPreference = "Continue"

$azCopy = (Get-ChildItem -Path $azCopyDir -Recurse -File -Filter "azcopy.exe").FullName
Copy-Item $azCopy $using:azCopyPath