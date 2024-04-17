Configuration devops_test_server {

	param (
		[Parameter(Mandatory = $true)]
		[string]$hostName,

		[Parameter(Mandatory = $true)]
		[string]$yearRange = "2024-2025"
	)


	Import-DscResource -ModuleName PSDesiredStateConfiguration
	Import-DscResource -ModuleName DSCR_PowerPlan
	Import-DscResource -ModuleName WebAdministrationDsc
	Import-DscResource -ModuleName CertificateDsc

	$registryPathWSUS = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
	$registryPathAU = Join-Path $registryPathWSUS "\AU"

	$azureStorageRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecops/"
	$dsoStorageRoot = $azureStorageRoot + "scripts/DSC/Resources"
	$dsoAppLockerRoot = $azureStorageRoot + "scripts/DSC/AppLocker"
	$dsoUpdateRoot = $azureStorageRoot + "scripts/Update"
	$azCopyDownloadUrl = "https://aka.ms/downloadazcopy-v10-windows"

	$dsoRoot = 'C:\egobrane\$DevSecOps'
	$gpoType = "egobranecom-nightlytest"
	$geocodePath = "C:\ProgramData\egobrane\egobraneWeb_Default"
	$dsoLocalStorageRoot = Join-Path $dsoRoot "Resources"
	$azCopyPath = Join-Path $dsoRoot "azcopy.exe"
	$policyPath = Join-Path $dsoRoot "Applocker-Global-pol.xml"

	$sslThumbprint = Get-AutomationVariable -Name "$yearRange-egobranenet-thumbprint"
	$egobraneNetCert = Get-AutomationPSCredential -Name "$yearRange-egobranenet-cert"
	$productKey2016 = Get-AutomationVariable -Name "Server2016Key"
	$productKey2022 = Get-AutomationVariable -Name "Server2022Key"
	$domainJoinUser = Get-AutomationVariable -Name "domainJoinSvc"
	$domainJoinPass = Get-AutomationVariable -Name "domainJoinSecret"
	$egobranelaPass = Get-AutomationPSCredential -Name "$hostName-egobranela"
	$teamcityPass = Get-AutomationPSCredential -Name "teamcity-cred"


	Node $hostName {


		Registry WSUSTrustedPublisherCerts
		{
			Ensure    = "Present"
			Key       = $registryPathWSUS
			ValueName = "AcceptTrustedPublisherCerts"
			ValueType = "Dword"
			ValueData = "1"
			Force     = $true
		}

		Registry WUServer
		{
			Ensure    = "Present"
			Key       = $registryPathWSUS
			ValueName = "WUServer"
			ValueType = "String"
			ValueData = "https://wsus2019.egobranenet.com:8531"
			Force     = $true
		}

		Registry WSUSStatusServer
		{
			Ensure    = "Present"
			Key       = $registryPathWSUS
			ValueName = "WUStatusServer"
			ValueType = "String"
			ValueData = "https://wsus2019.egobranenet.com:8531"
			Force     = $true
		}

		Registry AUOptions
		{
			Ensure    = "Present"
			Key       = $registryPathAU
			ValueName = "AUOptions"
			ValueType = "Dword"
			ValueData = "4"
			Force     = $true
		}

		Registry IncludeRecommendedUpdates
		{
			Ensure    = "Present"
			Key       = $registryPathAU
			ValueName = "IncludeRecommendedUpdates"
			ValueType = "Dword"
			ValueData = "1"
			Force     = $true
		}

		Registry UseWUServer
		{
			Ensure    = "Present"
			Key       = $registryPathAU
			ValueName = "UseWUServer"
			ValueType = "Dword"
			ValueData = "1"
			Force     = $true
		}

		Registry FIPSAlgorithmPolicy
		{
			Ensure    = "Present"
			Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
			ValueName = "Enabled"
			ValueType = "Dword"
			ValueData = "1"
			Force     = $true
		}

		Registry NetLogonDisablePasswordchange
		{
			Ensure    = "Present"
			Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters"
			ValueName = "DisablePasswordChange"
			ValueType = "Dword"
			ValueData = "1"
			Force     = $true
		}

		Registry TokenFilterPolicy
		{
			Ensure    = "Present"
			Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			ValueName = "LocalAccountTokenFilterPolicy"
			ValueType = "Dword"
			ValueData = "1"
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

		User Teamcity
		{
			Ensure                 = "Present"
			Disabled               = $false
			UserName               = "teamcity"
			FullName               = "teamcity"
			Password               = $teamcityPass
			PasswordChangeRequired = $false
			PasswordNeverExpires   = $true
		}

		WindowsFeatureSet DMZStorageServices
		{
			Name   = @(
				"FileAndStorage-Services"
				"Storage-Services"
			)
			Ensure = "Present"
		}

		WindowsFeatureSet DMZNETFramework
		{
			Name      = @(
				"NET-Framework-Features"
				"NET-Framework-Core"
				"NET-Framework-45-Features"
				"NET-Framework-45-Core"
				"NET-Framework-45-ASPNET"
				"NET-WCF-Services45"
				"NET-WCF-TCP-PortSharing45"
			)
			Ensure    = "Present"
			DependsOn = "[Script]DownloadNet35"
		}

		WindowsFeatureSet WebServer
		{
			Name      = @(
				"Web-Server"
				"Web-WebServer"
				"Web-Common-Http"
				"Web-Default-Doc"
				"Web-Dir-Browsing"
				"Web-Http-Errors"
				"Web-Static-Content"
				"Web-Http-Redirect"
				"Web-Health"
				"Web-Http-Logging"
				"Web-Request-Monitor"
				"Web-Performance"
				"Web-Stat-Compression"
				"Web-Security"
				"Web-Filtering"
				"Web-Windows-Auth"
				"Web-App-Dev"
				"Web-Net-Ext45"
				"Web-Asp-Net45"
				"Web-Net-Ext"
				"Web-AppInit"
				"Web-ASP"
				"Web-Asp-Net"
				"Web-ISAPI-Ext"
				"Web-ISAPI-Filter"
				"Web-WebSockets"
				"Web-Mgmt-Tools"
				"Web-Mgmt-Console"
			)   
			Ensure    = "Present"
			DependsOn = "[Script]DownloadNet35"
		}

		WebSite SSLBindings
		{
			Ensure      = "Present"
			Name        = "Default Web Site"
			DependsOn   = @(
				"[PfxImport]egobraneNet"
				"[WindowsFeatureSet]WebServer"
			)
			BindingInfo = @(
				DSC_WebBindingInformation
				{
					Protocol              = "HTTPS"
					Port                  = "443"
					CertificateStoreName  = "MY"
					CertificateThumbprint = $sslThumbprint
					IPAddress             = "*"
				}
				DSC_WebBindingInformation
				{
					Protocol  = "HTTP"
					Port      = "80"
					IPAddress = "*"
				}
			)
		}

		PfxImport egobraneNet
		{
			Thumbprint   = $sslThumbprint
			Path         = "$dsoLocalStorageRoot\STAR_egobranenet_com_$yearRange.pfx"
			Location     = "LocalMachine"
			Store        = "My"
			Credential   = $egobraneNetCert
			Ensure       = "Present"
			FriendlyName = "*.egobranenet.com $yearRange"
			DependsOn    = "[Script]CertDownload"
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

		Script SetAzCopyVariables
		{
			TestScript = {
				if ((($env:AZCOPY_AUTO_LOGIN_TYPE) -eq "MSI") -and (($env:AZCOPY_DISABLE_SYSLOG) -eq "true"))
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				[Environment]::SetEnvironmentVariable("AZCOPY_AUTO_LOGIN_TYPE", "MSI", "Machine")
				[Environment]::SetEnvironmentVariable("AZCOPY_DISABLE_SYSLOG", "true", "Machine")
			}
			GetScript  = {
				@{ Result = ($env:AZCOPY_AUTO_LOGIN_TYPE, $env:AZCOPY_DISABLE_SYSLOG) }
			}
			DependsOn  = "[Script]DownloadAzCopy"
		}

		Script SetDevSecOpsPermissions
		{
			TestScript = {
				$desiredACLAssignments = @(
					'NT AUTHORITY\Authenticated Users'
					'NT AUTHORITY\SYSTEM'
				)
				$desiredACLPermissions = @(
					'ReadAndExecute, Synchronize'
					'FullControl'
				)

				$fileTree = @((Get-ChildItem -Path $using:dsoRoot -Recurse | Select-Object FullName).FullName) + @($using:dsoRoot)
				foreach ($file in $fileTree)
				{
					[Array]$ACLAssignments = @(($ACLAssignments) + (((Get-Acl -Path $file).Access.IdentityReference | Sort-Object Value).Value))
					[Array]$ACLPermissions = @(($ACLPermissions) + (((Get-Acl -Path $file).Access | Sort-Object FileSystemRights).FileSystemRights))
				}
				$currentACLAssignments = $ACLAssignments | Select-Object -Unique
				$currentACLPermissions = $ACLPermissions | Select-Object -Unique
				
				$assignmentMatch = @(Compare-Object -ReferenceObject @($desiredACLAssignments | Select-Object) `
						-DifferenceObject @($currentACLAssignments | Select-Object)).Length -eq 0 | Out-String -Stream
				$permissionMatch = @(Compare-Object -ReferenceObject @($desiredACLPermissions | Select-Object) `
						-DifferenceObject @($currentACLPermissions | Select-Object)).Length -eq 0 | Out-String -Stream

				if (($assignmentMatch -eq 'True') -and ($permissionMatch -eq 'True'))
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$userSYSTEM = "NT AUTHORITY\SYSTEM"
				$groupAuthenticatedUsers = "NT AUTHORITY\Authenticated Users"

				#Set SYSTEM Full access and ownership
				$acl = Get-Acl -Path $using:dsoRoot
				$accessRuleSYSTEM = New-Object System.Security.AccessControl.FileSystemAccessRule ($userSYSTEM, "FullControl,TakeOwnership,ChangePermissions", "ContainerInherit,ObjectInherit", "None", "Allow")
				$acl.SetAccessRule($accessRuleSYSTEM)
				$acl | Set-Acl -Path $using:dsoRoot
				icacls.exe $using:dsoRoot /setowner $userSYSTEM /t

				#Disable inheritance
				$acl.SetAccessRuleProtection($true, $false)
				$acl | Set-Acl -Path $using:dsoRoot

				#Remove extra explicit permissions
				$fileTree = @((Get-ChildItem -Path $using:dsoRoot -Recurse | Select-Object FullName).FullName) + @($using:dsoRoot)
				foreach ($file in $fileTree)
				{
					[System.Collections.ArrayList]$identityArray = $identityArray + @((Get-Acl -Path $file).Access.IdentityReference.Value)
				}
				
				while (($identityArray -contains $groupAuthenticatedUsers) -or ($identityArray -contains $userSYSTEM))
				{
					$identityArray.Remove($groupAuthenticatedUsers)
					$identityArray.Remove($userSYSTEM)
				}
				
				foreach ($file in $fileTree)
				{
					[array]$identitySearch = (Get-Acl -Path $file).Access.IdentityReference.Value
					if (($identitySearch | ForEach-Object{ $identityArray.Contains($_) }) -contains $true)
					{
						foreach ($identity in $identityArray)
						{
							$userSID = New-Object System.Security.Principal.NTAccount ($identity)
							$acl.PurgeAccessRules($userSID)
							$acl | Set-Acl -Path $file
						}
					}
				}

				#Set Authenticated Users read and execute access
				$accessRuleAuthenticatedUsers = New-Object System.Security.AccessControl.FileSystemAccessRule ($groupAuthenticatedUsers, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
				$acl.SetAccessRule($accessRuleAuthenticatedUsers)
				$acl | Set-Acl -Path $using:dsoRoot

				#Set SYSTEM ownership on root
				icacls.exe $using:dsoRoot /setowner $userSYSTEM
			}
			GetScript  = {
				@{ Result = (Get-Acl -Path $using:dsoRoot) }
			}
			DependsOn  = "[File]DevSecOps"
		}

		Script SetFolderOptions
		{
			TestScript = {
				New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
				$profileSIDs = @((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object { $_.ProfileImagePath -like "C:\Users\*" -and $_.ProfileImagePath -notlike "C:\Users\default*" }).PSChildName)
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
			}
			SetScript  = {
				Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt -Name "DefaultValue" -Value 0 -Force -ErrorAction SilentlyContinue
				New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
				$profileSIDs = @((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object { $_.ProfileImagePath -like "C:\Users\*" -and $_.ProfileImagePath -notlike "C:\Users\default*" }).PSChildName)
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
			}
			GetScript  = {
				@{ Result = (Write-Host "Registry check") }
			}
		}
		
		Script WindowsProductKey 
		{
			TestScript = {
				$operatingSystem = (Get-ComputerInfo).OsName
				if ($operatingSystem -like "*2016*")
				{
					$productKeyExpression = $using:productKey2016
				}
				elseif ($operatingSystem -like "*2022*")
				{
					$productKeyExpression = $using:productKey2022
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
			}
			SetScript  = {
				$operatingSystem = (Get-ComputerInfo).OsName
				if ($operatingSystem -like "*2016*")
				{
					$productKey = $using:productKey2016
				}
				elseif ($operatingSystem -like "*2022*")
				{
					$productKey = $using:productKey2022
				}
				else
				{
					Write-Host "Operating System type invalid for this script. Required: Server 2016 or 2022"
				}
				$sLmgr = 'C:\Windows\System32\slmgr.vbs'
				$cScript = 'C:\Windows\System32\cscript.exe'
				Start-Process -FilePath $cScript -ArgumentList ($sLmgr, '-ipk', $productKey) | Out-Null
				Start-Process -FilePath $cScript -ArgumentList ($sLmgr, '-ato')
			}
			GetScript  = {
				@{ Result = ((Get-WmiObject -Query 'select * from SoftwareLicensingService').OA3xOriginalProductKey) }
			}
		}

		Script RedirectDownload
		{
			TestScript = {
				$indexPath = "C:\inetpub\wwwroot\index.htm"
				if ((Test-Path -Path $indexPath) -and ((Get-Content -Path $indexPath |
							Out-String -Stream) -like "*./egobraneweb*"))
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$indexPath = "C:\inetpub\wwwroot\index.htm"
				Get-ChildItem "C:\inetpub\wwwroot\" -Exclude "web.config" | Remove-Item -Force -Confirm -ErrorAction SilentlyContinue
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/Redirects/nightlytestindex.htm" `
						$indexPath --overwrite=true --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
			}
			GetScript  = {
				@{ Result = ((Get-Content -Path "C:\inetpub\wwwroot\index.htm")) }
			}
			DependsOn  = "[Script]SetAzCopyVariables"
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
			SetScript  = {
				$result = (& $using:azCopyPath copy "$using:dsoUpdateRoot/AutoUpdate.ps1" `
						"$using:dsoRoot\AutoUpdate.ps1" --overwrite=true --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
				powershell.exe -ExecutionPolicy Bypass -File "$using:dsoRoot\AutoUpdate.ps1"
			}
			GetScript  = {
				@{ Result = (Get-ScheduledTask -TaskName "egobrane Updates" -ErrorAction SilentlyContinue) }
			}
			DependsOn  = "[Script]SetAzCopyVariables"
		}

		Script DownloadNet48
		{
			TestScript = {
				Remove-Item "$using:dsoLocalResources\ndp48-x86-x64-allos-enu.exe" -Force -Confirm -ErrorAction SilentlyContinue
				if ((Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release) -ge 528040)
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/Tools/ndp48-x86-x64-allos-enu.exe" `
						"$using:dsoLocalResources\ndp48-x86-x64-allos-enu.exe" --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
				(& "$using:dsoLocalResources\ndp48-x86-x64-allos-enu.exe" /q)
			}
			GetScript  = {
				@{ Result = (Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release) }
			}
			DependsOn  = "[Script]SetAzCopyVariables"
		}

		Script DownloadNet35
		{
			TestScript = {
				Remove-Item "$using:dsoLocalResources\microsoft-windows-netfx3-ondemand-package~31bf3856ad364e35~amd64~~.cab" `
					-Force -Confirm -ErrorAction SilentlyContinue
				(Get-ChildItem -Path 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
				Get-ItemProperty -Name 'Version' -ErrorAction SilentlyContinue |
				ForEach-Object { $_.Version -as [System.Version] } | Where-Object { $_.Major -eq 3 }).Count -ge 1
			}
			SetScript  = {
				$DISM = 'C:\Windows\System32\Dism.exe'
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/Tools/microsoft-windows-netfx3-ondemand-package~31bf3856ad364e35~amd64~~.cab" `
						"$using:dsoLocalResources\microsoft-windows-netfx3-ondemand-package~31bf3856ad364e35~amd64~~.cab" --output-level="essential") |
				Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
				(& $DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /source:$using:dsoLocalResources)
			}
			GetScript  = {
				@{ Result = (Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
						Get-ItemProperty -Name 'Version' -ErrorAction SilentlyContinue |
						ForEach-Object { $_.Version -as [System.Version] } | Where-Object { $_.Major -eq 3 }) 
    }
			}
			DependsOn  = "[Script]SetAzCopyVariables"
		}

		Script DownloadMSOLEDBSQL
		{
			TestScript = {
				Remove-Item "$using:dsoLocalResources\msoledbsql_18.6.7_x64_recommended.msi" `
					-Force -Confirm -ErrorAction SilentlyContinue
				if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\MSOLEDBSQL' -ErrorAction SilentlyContinue).InstalledVersion -ne $null)
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$msoledbsqlPath = Join-Path $using:dsoLocalResources "msoledbsql_18.6.7_x64_recommended.msi"
				$result = (& $using:azCopyPath copy "$using:dsoUpdateRoot/packages/msoledbsql_18.6.7_x64_recommended.msi" `
						$msoledbsqlPath --output-level="essential") |
				Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
				(& $msoledbsqlPath IACCEPTMSOLEDBSQLLICENSETERMS=YES /qn)
			}
			GetScript  = {
				@{ Result = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\MSOLEDBSQL').InstalledVersion }
			}
			DependsOn  = "[Script]SetAzCopyVariables"
		}

		Script DownloadGeocodeData
		{
			TestScript = {
				$geocodeReferenceData = "FL_tiger.sqlite", "KS_tiger.sqlite", "TX_tiger.sqlite"
				$geocodeDifferenceData = (Get-ChildItem "$using:geocodePath\GeocodeData" -ErrorAction SilentlyContinue).Name
				$geocodeIsPresent = @(Compare-Object -ReferenceObject @($geocodeReferenceData | Select-Object) `
						-DifferenceObject @($geocodeDifferenceData | Select-Object)).Length -eq 0
				$geocodeIsPresent
			}
			SetScript  = {
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/GeocodeData" `
						"$using:geocodePath" --recursive=true) | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
			}
			GetScript  = {
				@{ Result = (Get-ChildItem "$using:geocodePath\GeocodeData" -ErrorAction SilentlyContinue) }
			}
			DependsOn  = "[Script]SetAzCopyVariables"
		}
		
		Script DuoInstall
		{
			TestScript = {
				$duoInstall = "Duo Authentication for Windows Logon x64"
				$installed = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
					Where-Object { $_.DisplayName -eq $duoInstall }) -ne $null
				Remove-Item "$using:dsoLocalResources\duo-installer.exe" -Force -Confirm -ErrorAction SilentlyContinue
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
				$result = (& $using:azCopyPath copy "$using:dsoUpdateRoot/packages/duo-win-login-4.2.2.exe" `
						$duoPath --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
				(& $duoPath /S /V`" /qn IKEY=`"$using:IKey`" SKEY=`"$using:SKey`" HOST="api-7fe218fe.duosecurity.com" AUTOPUSH="#1" FAILOPEN="#0" RDPONLY="#0" UAC_PROTECTMODE="#2"`") 
			}
			GetScript  = {
				@{ Result = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
						Where-Object { $_.DisplayName -eq "Duo Authentication for Windows Logon x64" }).DisplayName 
    }
			}
			DependsOn  = @(
				"[Script]SetAzCopyVariables"
				"[Script]DomainJoin"
			)
		}

		Script CertDownload
		{
			TestScript = {
				Remove-Item "$using:dsoLocalStorageRoot\STAR_egobranenet_com_$using:YearRange.pfx" -Force -Confirm -ErrorAction SilentlyContinue
				if (Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.FriendlyName -like "*$using:YearRange*" })
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$operatingSystem = (Get-ComputerInfo).OsName
				if ($operatingSystem -like "*2016*")
				{
					$targetCert = "$using:dsoStorageRoot/Certs/STAR_egobranenet_com_$using:yearRange.legacy.pfx"
				}
				elseif ($operatingSystem -like "*2022*")
				{
					$targetCert = "$using:dsoStorageRoot/Certs/STAR_egobranenet_com_$using:yearRange.pfx"
				}
				$result = (& $using:azCopyPath copy $targetCert	"$using:dsoLocalStorageRoot\STAR_egobranenet_com_$using:yearRange.pfx" --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
			}
			GetScript  = {
				@{
					GetScript  = $GetScript
					SetScript  = $SetScript
					TestScript = $TestScript
					Result     = ('True' -in (Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.FriendlyName -like "*$using:yearRange*" }))
				}
			}
			DependsOn  = "[Script]SetAzCopyVariables"
		}

		Script DomainJoin
		{
			Testscript = {
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
		
		Script EnableRDPRegistry
		{
			TestScript = {
				$tsRegistryKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
				$winStationsRegistryKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

				$fDenyTSConnectionsRegistry = (Get-ItemProperty -Path $tsRegistryKey -Name 'fDenyTSConnections').fDenyTSConnections
				$userAuthenticationRegistry = (Get-ItemProperty -Path $winStationsRegistryKey -Name 'UserAuthentication').UserAuthentication

				if (($fDenyTSConnectionsRegistry -eq 0) -and ($userAuthenticationRegistry -eq 1))
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$tsRegistryKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
				$winStationsRegistryKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

				Set-ItemProperty -Path $tsRegistryKey -Name 'fDenyTSConnections' -Value 0
				Set-ItemProperty -Path $winStationsRegistryKey -Name 'UserAuthentication' -Value 1
			}
			GetScript  = {
				@{ Result = (Get-ItemProperty -Path ($tsRegistryKey, $winStationsRegistryKey)) }
			}
		}

		Script SetTimeZone
		{
			TestScript = {
				if ((Get-TimeZone).Id -eq 'Eastern Standard Time')
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				Set-TimeZone -Name 'Eastern Standard Time'
			}
			GetScript  = {
				@{ Result = (Get-TimeZone) }
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
				@{ Result = (Get-NetFirewallRule -DisplayGroup "Remote Desktop").DisplayName }
			}
		}

		Script EnableFilePrinterSharing
		{
			TestScript = {
				if ((Get-NetFirewallRule -DisplayGroup "File and Printer Sharing").Enabled -ne "True")
				{
					$false
				}
				else
				{
					$true
				}
			}
			SetScript  = {
				Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
			}
			GetScript  = {
				@{ Result = (Get-NetFirewallRule -DisplayGroup "File and Printer Sharing").DisplayName }
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

		Script WsManSettings
		{
			TestScript = {
				if((Get-Item WSMan:\localhost\Client\TrustedHosts).Value -eq "*" -and `
					(Get-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB).Value -eq "512")
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
				Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 512
			}
			GetScript  = {
				@{ Result = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value }
			}
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
				@{ Result = (Get-LocalUser -Name "Administrator") }
			}
			DependsOn  = "[User]egobranela"
		}

		Script LocalAdministratorGroup
		{
			TestScript = {
				if (((Get-LocalGroupMember -Group "Administrators").Name -like "$using:hostName\egobranela") -and `
					((Get-LocalGroupMember -Group "Administrators").Name -like "$using:hostName\teamcity"))
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				Add-LocalGroupMember -Group "Administrators" -Member "egobranela", "teamcity" -ErrorAction SilentlyContinue
			}
			GetScript  = {
				@{ Result = (Get-LocalGroupMember -Group "Administrators") }
			}
			DependsOn  = @(
				"[User]egobranela"
				"[User]Teamcity"
				"[Script]DomainJoin"
			)
		}

		Script RemoveXPoweredHeader
		{
			TestScript = {
				if ((Get-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']").Name -like 'X-Powered-By')
				{
					$false 
				}
				else
				{
					$true 
				}                    
			}
			SetScript  = {
				Clear-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']"
			}
			GetScript  = {
				@{ Result = (Get-WebConfiguration "system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']" | Out-String -Stream ) }
			}
			DependsOn  = "[WindowsFeatureSet]WebServer"
		}

		Script SetTransportHeader
		{
			TestScript = {
				if ((Get-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders/add" -PSPath "IIS:\Sites\Default Web Site" -Name value |
						Out-String -Stream) -like "*Strict-Transport-Security*")
				{
					$true 
				}
				else
				{
					$false 
				}
			}
			SetScript  = {
				Add-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" -PSPath "IIS:\Sites\Default Web Site" -Name . -Value @{name = "Strict-Transport-Security"; value = "max-age=31536000; includeSubDomains" }
			}
			GetScript  = {
				@{ Result = (Get-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders/add" -PSPath "IIS:\Sites\Default Web Site" -Name value | Out-String -Stream ) }
			}
			DependsOn  = "[WindowsFeatureSet]WebServer"
		}

		Script CryptoWebServerStrict
		{
			TestScript = {
				$schannelRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\'

				$intendedCipherArray = @(
					'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
					'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
					'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
					'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
					'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
					'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
				)
				$intendedTLSArray = @(
					'0',
					'0',
					'0',
					'0',
					'0',
					'0',
					'0',
					'0',
					'0',
					'0',
					'0',
					'0',
					'4294967295',
					'4294967295'
				)
				$currentCipherArray = (Get-TlsCipherSuite | Sort-Object -Property BasecipherSuite -Descending).Name
				$ErrorActionPreference = "SilentlyContinue"
				$currentTLSArray = Get-ItemPropertyValue -Path $schannelRegistryPath\Protocols\*\* -Name Enabled
				$ErrorActionPreference = "Continue"
				$cipherMatch = @(Compare-Object -ReferenceObject @($intendedCipherArray) `
						-DifferenceObject @($currentCipherArray)).Length -eq 0 | Out-String -Stream
				$tlsMatch = @(Compare-Object -ReferenceObject @($intendedTLSArray) `
						-DifferenceObject @($currentTLSArray)).Length -eq 0 | Out-String -Stream
				if ($cipherMatch -eq 'True' -and $tlsMatch -eq 'True')
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$schannelRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\'
				$mpuhPath = Join-Path $schannelRegistryPath "\Protocols\Multi-Protocol Unified Hello"
				$pct10Path = Join-Path $schannelRegistryPath "\Protocols\PCT 1.0"
				$ssl20Path = Join-Path $schannelRegistryPath "\Protocols\SSL 2.0"
				$ssl30Path = Join-Path $schannelRegistryPath "\Protocols\SSL 3.0"
				$tls10Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.0"
				$tls11Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.1"
				$tls12Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.2"

				#Disable Insecure Protocols
				$insecureProtocolPathArray = @(
					$mpuhPath,
					$pct10Path,
					$ssl20Path,
					$ssl30Path,
					$tls10Path,
					$tls11Path
				)

				foreach ($insecureProtocol in $insecureProtocolPathArray)
				{
					New-Item "$insecureProtocol\Server" -Force | Out-Null
					New-ItemProperty -Path "$insecureProtocol\Server" -Name Enabled -Value 0 -PropertyType 'Dword' -Force | Out-Null
					New-ItemProperty -Path "$insecureProtocol\Server" -Name "DisabledByDefault" -Value 1 -PropertyType 'Dword' -Force | Out-Null
					New-Item "$insecureProtocol\Client" -Force | Out-Null
					New-ItemProperty -Path "$insecureProtocol\Client" -Name Enabled -Value 0 -PropertyType 'Dword' -Force | Out-Null
					New-ItemProperty -Path "$insecureProtocol\Client" -Name "DisabledByDefault" -Value 1 -PropertyType 'Dword' -Force | Out-Null
				}

				$secureProtocolArray = @(
					$tls12Path
				)

				#Enable Secure Protocols
				foreach ($secureProtocol in $secureProtocolArray)
				{
					New-Item "$secureProtocol\Server" -Force | Out-Null
					New-ItemProperty -Path "$secureProtocol\Server" -Name Enabled -Value '0xffffffff' -PropertyType 'Dword' -Force | Out-Null
					New-ItemProperty -Path "$secureProtocol\Server" -Name "DisabledByDefault" -Value 0 -PropertyType 'Dword' -Force | Out-Null
					New-Item "$secureProtocol\Client" -Force | Out-Null
					New-ItemProperty -Path "$secureProtocol\Client" -Name Enabled -Value '0xffffffff' -PropertyType 'Dword' -Force | Out-Null
					New-ItemProperty -Path "$secureProtocol\Client" -Name "DisabledByDefault" -Value 0 -PropertyType 'Dword' -Force | Out-Null
				}

				# Disable Insecure Ciphers
				$insecureCiphers = @(
					'DES 56/56',
					'NULL',
					'RC2 128/128',
					'RC2 40/128',
					'RC2 56/128',
					'RC4 40/128',
					'RC4 56/128',
					'RC4 64/128',
					'RC4 128/128',
					'Triple DES 168'
				)

				foreach ($insecureCipher in $insecureCiphers)
				{
					$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
					$key.SetValue('Enabled', 0, 'Dword')
					$key.Close()
				}

				# Enable Secure Ciphers
				$secureCiphers = @(
					'AES 128/128',
					'AES 256/256'
				)

				foreach ($secureCipher in $secureCiphers)
				{
					$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
					New-ItemProperty -Path "$schannelRegistryPath\Ciphers\$secureCipher" -Name Enabled -Value '0xffffffff' -PropertyType 'Dword' -Force | Out-Null
					$key.Close()
				}


				# Set Hashes Configuration
				New-Item "$schannelRegistryPath\Hashes" -Force | Out-Null

				$secureHashes = @(
					'MD5',
					'SHA',
					'SHA256',
					'SHA384',
					'SHA512'
				)

				foreach ($secureHash in $secureHashes)
				{
					$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
					New-ItemProperty -Path "$schannelRegistryPath\Hashes\$secureHash" -Name Enabled -Value '0xffffffff' -PropertyType 'Dword' -Force | Out-Null
					$key.Close()
				}

				# Set Key Exchange Algorithms
				New-Item "$schannelRegistryPath\KeyExchangeAlgorithms" -Force | Out-Null

				$secureKeyExchangeAlgorithms = @(
					'Diffie-Hellman',
					'ECDH',
					'PKCS'
				)

				foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms)
				{
					$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
					New-ItemProperty -Path "$schannelRegistryPath\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -Name Enabled -Value '0xffffffff' -PropertyType 'Dword' -Force | Out-Null
					$key.Close()
				}

				# Configure Longer DHE Keys
				New-ItemProperty -Path "$schannelRegistryPath\KeyExchangeAlgorithms\Diffie-Hellman" -Name "ServerMinKeyBitLength" -Value '2048' -PropertyType 'Dword' -Force | Out-Null

				# Enable Strict Web Server Cipher Suites
				$cipherSuitesOrder = @(
					'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
					'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
					'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
					'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
					'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
					'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
				)
				$cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
				New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name "Functions" -Value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null
				New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name "SchUseStrongCrypto" -Value 1 -PropertyType 'Dword' -Force | Out-Null
				New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -name "SchUseStrongCrypto" -Value 1 -PropertyType 'Dword' -Force | Out-Null
			}
			GetScript  = {
				@{ Result = (Get-ItemPropertyValue -Path $schannelRegistryPath\Protocols\*\* -Name Enabled) }
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
				$result = (& $using:azCopyPath copy "$using:dsoAppLockerRoot/Applocker-Global-pol.xml" `
						"$using:policyPath" --overwrite=ifSourceNewer --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					$result = (& $using:azCopyPath copy "$using:dsoAppLockerRoot/Applocker-Global-pol.xml" `
							"$using:policyPath" --overwrite=ifSourceNewer --output-level="essential") | Out-String
					if($LASTEXITCODE -ne 0)
					{
						throw (("Copy error. $result"))
					}
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
			DependsOn  = "[Script]SetAzCopyVariables"
		}

		Script GPOSettings
		{
			TestScript = {
				if ((Get-WmiObject Win32_ComputerSystem).Domain -eq "egobraneNET.com")
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$lgpoPath = Join-Path $using:dsoLocalStorageRoot "\Tools\LGPO.exe"
				$gpoPath = Join-Path $using:dsoLocalStorageRoot "\Group Policy\$using:gpoType.PolicyRules"

				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/Tools/LGPO.exe" `
						$lgpoPath --overwrite=ifSourceNewer --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}

				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/Group Policy/$using:gpoType.PolicyRules" `
						$gpoPath --overwrite=ifSourceNewer --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}

				(& $lgpoPath /q /p $gpoPath)
			}
			GetScript  = {
				@{ Result = (Get-Item "$using:dsoLocalStorageRoot\Group Policy\*.PolicyRules" -ErrorAction SilentlyContinue) }
			}
		}
	}
}