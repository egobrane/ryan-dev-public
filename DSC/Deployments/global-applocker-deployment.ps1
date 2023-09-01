Configuration GlobalApplockerDeploymentv4 {

	#This current version uses AzCopy to download new policies and apply them if changes have been made. 
	#XML Policy storage is still located in DevSecOpsDev for the time being. 
	param (
		[Parameter(Mandatory = $true)]
		[string]$HostName = 'localhost'
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration

	$dsoAppLockerRoot = "https://nope.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/AppLocker"
	$dsoRoot = 'C:\nope\$DevSecOps'
	$policyPath = Join-Path $dsoRoot "Applocker-Global-pol.xml"
	$azCopyPath = Join-Path $dsoRoot "azcopy.exe"
	$azCopyDownloadUrl = "https://aka.ms/downloadazcopy-v10-windows"

	Node $HostName {

		#Applocker depends on AppIDsvc running
		Service AppIDsvc
		{
			Name           = "AppIDSvc"
			State          = "Running"
			BuiltinAccount = "LocalService"
			DependsOn      = @(
				"[Script]PolicyUpdate"
			)
		}

		#AppIDsvc is now a protected service and cannot set startup type through services.msc - only registry or GPO
		Registry AutoStartupAppID
		{
			Ensure    = "Present"
			Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc"
			ValueName = "Start"
			ValueType = "Dword"
			ValueData = "2"
			Force     = $true
		}

		#Ensure DevSecOps folder is present and hidden
		File DevSecOps
		{
			Ensure          = "Present"
			Type            = "Directory"
			DestinationPath = $dsoRoot
			Attributes      = "Hidden"
		}

		#Download AzCopy if not present
		Script DownloadAzCopy
		{
			TestScript = {
				if("True" -in (Test-Path $using:azCopyPath))
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$progressPreference = "SilentlyContinue"
				$azCopyZipUrl = (Invoke-WebRequest -UseBasicParsing -Uri $using:azCopyDownloadUrl -MaximumRedirection 0 -ErrorAction SilentlyContinue).headers.location
				$azCopyZipFile = Split-Path $azCopyZipUrl -Leaf
				$azCopyZipPath = Join-Path $using:dsoRoot $azCopyZipFile
				$azCopyDir = Join-Path $using:dsoRoot "azcopy"

				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
				Invoke-WebRequest -UseBasicParsing -Uri $azCopyZipUrl -OutFile $azCopyZipPath
				Expand-Archive -Path $azCopyZipPath -DestinationPath $azCopyDir -Force
				$progressPreference = "Continue"

				$azCopy = (Get-ChildItem -Path $azCopyDir -Recurse -File -Filter "azcopy.exe").FullName
				Copy-Item $azCopy $using:azCopyPath
			}
			GetScript  = {
				@{ Result = (Test-Path $using:azCopyPath) }
			}
		}

		#Check if remote policy has changed and downloads latest policy if so
		Script PolicyUpdate
		{
			TestScript = {
				$false
			}
			SetScript  = {
				(& $using:azCopyPath login --identity --output-level="essential") | Out-Null
				$result = (& $using:azCopyPath copy "$using:dsoAppLockerRoot/Applocker-Global-pol.xml" `
						"$using:policyPath" --overwrite=ifSourceNewer --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
				Set-AppLockerPolicy -XmlPolicy "$using:policyPath"
			}
			GetScript  = {
				@{
					GetScript  = $GetScript
					SetScript  = $SetScript
					TestScript = $TestScript
					Result     = (Get-Content "$using:policyPath")
				}
			}
			DependsOn  = "[Script]DownloadAzCopy"
		}
	}
}