Configuration ManagementVMv3 {

	param (
		[Parameter(Mandatory = $true)]
		[string]$hostName
	)


	Import-DscResource -ModuleName PSDesiredStateConfiguration
	Import-DscResource -ModuleName DSCR_PowerPlan

	$registryPathControl = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control"

	$dsoStorageRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/Resources"
	$dsoAppLockerRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/AppLocker"
	$azCopyDownloadUrl = "https://aka.ms/downloadazcopy-v10-windows"

	$dsoRoot = 'C:\egobrane\$DevSecOps'
	$dsoLocalResources = Join-Path $dsoRoot "Resources"
	$azCopyPath = Join-Path $dsoRoot "azcopy.exe"
	$policyPath = Join-Path $dsoRoot "Applocker-Global-pol.xml"

	$productKey = Get-AutomationVariable -Name "Windows11KeyVL"
	$domainJoinUser = Get-AutomationVariable -Name "domainJoinSvc"
	$domainJoinPass = Get-AutomationVariable -Name "domainJoinSecret"
	$egobranelaPass = Get-AutomationPSCredential -Name "$hostName-egobranela"
	$iKey = Get-AutomationVariable -Name "DuoIKey"
	$sKey = Get-AutomationVariable -Name "DuoSKey"


	Node $hostName {

		Registry fDenyTSConnections
		{
			Ensure    = "Present"
			Key       = "$registryPathControl\Terminal Server"
			ValueName = "fDenyTSConnections"
			ValueType = "Dword"
			ValueData = "0"
			Force     = $true
		}

		Registry FIPSAlgorithmPolicy
		{
			Ensure    = "Present"
			Key       = "$registryPathControl\Lsa\FIPSAlgorithmPolicy"
			ValueName = "Enabled"
			ValueType = "Dword"
			ValueData = "1"
			Force     = $true
		}

		Registry fSingleSessionPerUser
		{
			Ensure    = "Present"
			Key       = "$registryPathControl\Terminal Server"
			ValueName = "fSingleSessionPerUser"
			ValueType = "Dword"
			ValueData = "0"
			Force     = $true
		}

		cPowerPlan Balanced
		{
			Ensure = "Present"
			GUID   = "SCHEME_BALANCED"
			Name   = "Balanced"
			Active = $true
		}

		cPowerPlanSetting MonitorTimeout
		{
			PlanGuid    = "SCHEME_BALANCED"
			SettingGuid = "VIDEOIDLE"
			Value       = 0
			AcDc        = "AC"
		}

		File egobrane
		{
			Ensure          = "Present"
			Type            = "Directory"
			DestinationPath = "C:\egobrane"
		}

		File Temp
		{
			Ensure          = "Present"
			Type            = "Directory"
			DestinationPath = "C:\Temp"
		}

		File DevSecOps
		{
			Ensure          = "Present"
			Type            = "Directory"
			DestinationPath = $dsoRoot
			Attributes      = "Hidden"
		}

		User egobranela
		{
			Ensure                 = "Present"
			Disabled               = $false
			UserName               = "egobranela"
			FullName               = "egobranela"
			Password               = $egobranelaPass
			PasswordChangeRequired = $false
			PasswordNeverExpires   = $true
		}

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
				$ProgressPreference = "SilentlyContinue"
				$azCopyZipUrl = (Invoke-WebRequest -UseBasicParsing -Uri $using:azCopyDownloadUrl -MaximumRedirection 0 -ErrorAction SilentlyContinue).headers.location
				$azCopyZipFile = Split-Path $azCopyZipUrl -Leaf
				$azCopyZipPath = Join-Path $using:dsoRoot $azCopyZipFile
				$azCopyDir = Join-Path $using:dsoRoot "azcopy"

				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
				Invoke-WebRequest -UseBasicParsing -Uri $azCopyZipUrl -OutFile $azCopyZipPath
				Expand-Archive -Path $azCopyZipPath -DestinationPath $azCopyDir -Force
				$ProgressPreference = "Continue"

				$azCopy = (Get-ChildItem -Path $azCopyDir -Recurse -File -Filter "azcopy.exe").FullName
				Copy-Item $azCopy $using:azCopyPath
			}
			GetScript  = {
				@{ Result = (Test-Path $using:azCopyPath) }
			}
			DependsOn  = "[File]DevSecOps"
		}

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
			DependsOn = "[Script]DownloadAzCopy"
		}

		Script WindowsProductKey
		{
			TestScript = {
				$productKeyExpression = $using:ProductKey
				$partialProductKey = $productKeyExpression.SubString($productKeyExpression.length - 5, 5)
				if ((Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object { $_.PartialProductKey -ne $null } |
						Select-Object -Property PartialProductKey | Out-String -Stream) -like "*$partialProductKey*")
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$slmgr = 'C:\Windows\System32\slmgr.vbs'
				$cScript = 'C:\Windows\System32\cscript.exe'
				Start-Process -FilePath $cScript -ArgumentList ($slmgr, '-ipk', $using:productKey) | Out-Null
				STart-Process -FilePath $cScript -ArgumentList ($slmgr, '-ato')
			}
			GetSCript  = {
				@{ Result = ((Get-WmiObject -Query 'select * from SoftwareLicensingService').OA3xOriginalProductKey) }
			}
		}

		Script DuoInstall
		{
			TestScript = {
				$duoInstall = "Duo Authentication for Windows Logon x64"
				$installed = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
					Where-Object { $_.DisplayName -eq $duoInstall }) -ne $null
				Remove-Item "$using:dsoRoot\duo-installer.exe" -Force -Confirm -ErrorAction SilentlyContinue
				if (-Not $installed)
				{
					$false
				}
				else
				{
					$true
				}
			}
			SetScript  = {
				$duoPath = Join-Path $using:dsoLocalResources "duo-installer.exe"
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/duo-win-login-4.2.0.exe" `
						$duoPath --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
				(& $duoPath /S /V`" /qn IKEY=`"$using:IKey`" SKEY=`"$using:SKey`" HOST="secret.duosecurity.com" AUTOPUSH="#1" FAILOPEN="#0" RDPONLY="#0" UAC_PROTECTMODE="#2"`")
			}
			GetScript  = {
				@{ Result = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -eq $duoInstall }) }
			}
			DependsOn  = @(
				"[Script]SetAzCopyAutoLoginVariable"
				"[Script]DomainJoin"
			)
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

		Script DownloadLogoffLogonAnnounce
		{
			TestScript = {
				if ((Test-Path "C:\egobrane\LogonAnnounce.exe") -and (Test-Path "C:\LogoffAnnounce.exe"))
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/LogonLogoffAnnounce/*" "C:\egobrane")
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
			}
			GetScript  = {
				@{ Result = (Get-Item "C:\egobrane\LogoffAnnounce.exe", "C:\egobrane\LogonAnnounce.exe") }
			}
			DependsOn  = "[Script]SetAzCopyAutoLoginVariable"
		}

		Script EnableRSAT
		{
			TestScript = {
				$intendedCapabilities = @(
					'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
					'Rsat.DHCP.Tools~~~~0.0.1.0'
					'Rsat.Dns.Tools~~~~0.0.1.0'
					'Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0'
					'Rsat.FileServices.Tools~~~~0.0.1.0'
					'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
					'Rsat.ServerManager.Tools~~~~0.0.1.0'
					'Rsat.WSUS.Tools~~~~0.0.1.0'
				)
				$currentCapabilities = (Get-WindowsCapability -Name Rsat* -Online |
					Where-Object { $_.State -eq "Installed" }).Name
				$capabilityMatch = @(Compare-Object -ReferenceObject @($intendedCapabilities | Select-Object) `
						-DifferenceObject @($currentCapabilities | Select-Object)).Length -eq 0
				$capabilityMatch
			}
			SetScript  = {
				$capabilityArray = @(
					'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
					'Rsat.DHCP.Tools~~~~0.0.1.0'
					'Rsat.Dns.Tools~~~~0.0.1.0'
					'Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0'
					'Rsat.FileServices.Tools~~~~0.0.1.0'
					'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
					'Rsat.ServerManager.Tools~~~~0.0.1.0'
					'Rsat.WSUS.Tools~~~~0.0.1.0'
				)
				foreach ($capability in $capabilityArray)
				{
					Add-WindowsCapability -Online -Name $capability
				}
			}
			GetScript  = {
				@{ Result = (Get-WindowsCapability -Name Rsat* -Online | Where-Object { $_.State -eq "Installed" }).Name }
			}
		}

		Script EnableHyperVFeatures
		{
			TestScript = {
				$intendedHyperVFeatures = @(
					'Microsoft-Hyper-V-All'
					'Microsoft-Hyper-V-Tools-All'
					'Microsoft-Hyper-V-Management-PowerShell'
					'Microsoft-Hyper-V-Management-Clients'
				)
				$currentHyperVFeatures = (Get-WindowsOptionalFeature -Online |
					Where-Object { ($_.FeatureName -like "Microsoft-Hyper-V*") -and ($_.State -eq "Enabled") }).FeatureName
				$featureMatch = @(Compare-Object -ReferenceObject @($intendedHyperVFeatures | Select-Object) `
						-DifferenceObject @($currentHyperVFeatures | Select-Object)).Length -eq 0
				$featureMatch
			}
			SetScript  = {
				$intendedHyperVFeatures = @(
					'Microsoft-Hyper-V-All'
					'Microsoft-Hyper-V-Tools-All'
					'Microsoft-Hyper-V-Management-PowerShell'
					'Microsoft-Hyper-V-Management-Clients'
				)
				foreach ($hyperVFeature in $intendedHyperVFeatures)
				{
					Enable-WindowsOptionalFeature -Online -FeatureName $hyperVFeature
				}
			}
			GetScript  = {
				@{ Result = (Get-WindowsOptionalFeature -Online | Where-Object { ($_.FeatureName -like "Microsoft-Hyper-V*") `
								-and ($_.State -eq "Enabled") }).FeatureName }
			}
		}

		Script EnableIISFeatures
		{
			TestScript = {
				$intendedIISFeatures = @(
					'IIS-WebServerRole'
					'IIS-WebServerManagementTools'
					'IIS-ManagementConsole'
				)
				$currentIISFeatures = (Get-WindowsOptionalFeature -Online |
					Where-Object { ($_.FeatureName -like "IIS*") -and ($_.State -eq "Enabled") }).FeatureName
				$featureMatch = @(Compare-Object -ReferenceObject @($intendedIISFeatures | Select-Object) `
						-DifferenceObject @($currentIISFeatures | Select-Object)).Length -eq 0
				$featureMatch
			}
			SetScript  = {
				Get-WindowsOptionalFeature -Online |
				Where-Object { ($_.FeatureName -like "IIS*") -and ($_.State -eq "Enabled") } |
				Disable-WindowsOptionalFeature -Online -NoRestart
				
				$intendedIISFeatures = @(
					'IIS-WebServerRole'
					'IIS-WebServerManagementTools'
					'IIS-ManagementConsole'
				)
				foreach ($IISFeature in $intendedIISFeatures)
				{
					Enable-WindowsOptionalFeature -Online -FeatureName $IISFeature -NoRestart
				}

				$unintendedIISFeatures = @(
					'IIS-WebServer'
					'IIS-CommonHttpFeatures'
					'IIS-HttpErrors'
					'IIS-ApplicationDevelopment'
					'IIS-Security'
					'IIS-RequestFiltering'
					'IIS-HealthAndDiagnostics'
					'IIS-HttpLogging'
					'IIS-Performance'
					'IIS-StaticContent'
					'IIS-DefaultDocument'
					'IIS-DirectoryBrowsing'
					'IIS-HttpCompressionStatic'
				)
				foreach ($IISFeature in $unintendedIISFeatures)
				{
					Disable-WindowsOptionalFeature -Online -FeatureName $IISFeature -NoRestart -ErrorAction SilentlyContinue
				}
				Restart-Computer -Force
			}
			GetScript  = {
				@{ Result = (Get-WindowsOptionalFeature -Online | Where-Object { ($_.FeatureName -like "IIS*") `
								-and ($_.State -eq "Enabled") }).FeatureName }
			}
		}

		Script EnableRDP
		{
			TestScript = {
				if ((Get-NetFirewallRule -DisplayGroup "Remote Desktop").Enabled -ne "True")
				{
					$false
				}
				else
				{
					$true
				}
			}
			SetScript  = {
				Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
			}
			GetScript  = {
				@{ Result = (Get-NetFirewallRule -DisplayGroup "Remote Desktop") }
			}
		}

		Script DisableNetworkDiscovery
		{
			TestScript = {
				if ((Get-NetFirewallRule -DisplayGroup "Network Discovery").Enabled -ne "False")
				{
					$false
				}
				else
				{
					$true
				}
			}
			SetScript  = {
				Disable-NetFirewallRule -DisplayGroup "Network Discovery"
			}
			GetScript  = {
				@{ Result = (Get-NetFirewallRule -DisplayGroup "Network Discovery").Enabled }
			}
		}

		Script ExecutionPolicyRemoteSigned
		{
			TestScript = {
				if ((Get-ExecutionPolicy) -eq "RemoteSigned")
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
				Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
			}
			GetScript  = {
				@{ Result = (Get-ExecutionPolicy) }
			}
		}

		Script LocalAdministratorGroupManagement
		{
			TestScript = {
				if (((Get-LocalGroupMember -Group "Administrators").Name | Out-String -Stream) -like '*egobraneCOM\$IG4000-2K1GJGFMV829*' `
						-and ((Get-LocalGroupMember -Group "Administrators").Name | Out-String -Stream) -like '*egobranela*')
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				Add-LocalGroupMember -Group "Administrators" -Member 'egobraneCOM\$IG4000-2K1GJGFMV829', 'egobranela' -ErrorAction SilentlyContinue
			}
			GetScript  = {
				@{ Result = (Get-LocalGroupMember -Group "Administrators" | Out-String -Stream) }
			}
			DependsOn  = @(
				"[Script]DomainJoin"
				"[User]egobranela"
			)
		}

		Script DisableLocalAdministrator
		{
			TestScript = {
				if ((Get-LocalUser -Name "Administrator").Enabled -eq "True")
				{
					$false
				}
				else
				{
					$true
				}
			}
			SetScript  = {
				Disable-LocalUser -Name "Administrator"
			}
			GetScript  = {
				@{ Result = (Get-LocalUser -Name "Administrator").Enabled }
			}
		}
		Script TimeZone
		{
			TestScript = {
				if ((Get-TimeZone).Id -eq "Eastern Standard Time")
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				Set-TimeZone -Name "Eastern Standard Time"
			}
			GetScript  = {
				@{ Result = (Get-TimeZone) }
			}
		}

		Script DomainJoin
		{
			TestScript = {
				if (((Get-WmiObject Win32_ComputerSystem).Domain | Out-String -Stream) -like '*egobrane*' )
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				(Get-WmiObject -NameSpace "Root\Cimv2" -Class "Win32_ComputerSystem").JoinDomainOrWorkgroup("aad.egobrane.com", "$using:domainJoinPass", "$using:domainJoinUser", $null, 3)
				Restart-Computer -Force
			}
			GetScript  = {
				@{ Result = (Get-WmiObject Win32_ComputerSystem).Domain }
			}
		}

		#Begin AppLocker Configuration Block
		Service AppIDsvc
		{
			Name           = "AppIDSvc"
			State          = "Running"
			BuiltinAccount = "LocalService"
			DependsOn      = @(
				"[Script]PolicyUpdate"
			)
		}

		Registry AutoStartupAppID
		{
			Ensure    = "Present"
			Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc"
			ValueName = "Start"
			ValueType = "Dword"
			ValueData = "2"
			Force     = $true
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