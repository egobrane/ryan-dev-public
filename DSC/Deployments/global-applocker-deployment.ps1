Configuration GlobalApplockerDeploymentv3 {

	#This current version uses AzCopy to download new policies and apply them if changes have been made. 
	#XML Policy storage is still located in DevSecOpsDev for the time being. 
	param (
		[Parameter(Mandatory = $true)]
		[string]$HostName = 'localhost'
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration

	$dsoAppLockerRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/AppLocker"
	$dsoRoot = 'C:\egobrane\$DevSecOps'
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

		#Set AutoLogin for AzCopy
		Script SetAzCopyAutoLoginVariable
		{
			TestScript = {
				if (($env:AZCOPY_AUTO_LOGIN_TYPE) -eq "MSI")
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript = {
				[Environment]::SetEnvironmentVariable("AZCOPY_AUTO_LOGIN_TYPE", "MSI", "Machine")
			}
			GetScript = {
				@{ Result = ($env:AZCOPY_AUTO_LOGIN_TYPE) }
			}
		}		

		Script DownloadAutoUpdate
		{
			TestScript = {
				if ((Get-ScheduledTask -TaskName "egobrane Updates" -ErrorAction SilentlyContinue).TaskName -eq "egobrane Updates")
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript = {
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/AutoUpdate.ps1" `
					"$using:dsoRoot\AutoUpdate.ps1" --overwrite=true --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
				powershell.exe -ExecutionPolicy Bypass -File "$using:dsoRoot\AutoUpdate.ps1"
			}
			GetScript = {
				@{ Result = (Get-ScheduledTask -TaskName "egobrane Updates" -ErrorAction SilentlyContinue) }
			}
			DependsOn = "[Script]SetAzCopyAutoLoginVariable"
		}

		#Check if remote policy has changed and downloads latest policy if so
		Script PolicyUpdate
		{
			TestScript = {
				$false
			}
			SetScript  = {
				$attempt = 0
				do {
					$attempt++
					$result = (& $using:azCopyPath copy "$using:dsoAppLockerRoot/Applocker-Global-pol.xml" `
					"$using:policyPath" --overwrite-ifSourceNewer --output-level="essential") | Out-String
					if($LASTEXITCODE -eq 0) {break}
					if($attempt -ge 5)
					{
						throw (("Copy error. $result"))
					}
					$error.Clear()
					$LASTEXITCODE = 0
					Start-Sleep -Seconds 1
				} while ($attempt -le 5)
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
			DependsOn  = "[Script]SetAzCopyAutoLoginVariable"
		}
	}
}