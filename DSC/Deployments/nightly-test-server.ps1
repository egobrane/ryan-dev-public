Configuration NightlyTestServer {

	param (
		[Parameter(Mandatory = $true)]
		[string]$hostName
	)


	Import-DscResource -ModuleName PSDesiredStateConfiguration
	Import-DscResource -ModuleName DSCR_PowerPlan

	$registryPathWSUS = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
	$registryPathAU = Join-Path $registryPathWSUS "\AU"

	$dsoStorageRoot = "https://nope.blob.core.usgovcloudapi.net/nope/scripts/DSC/Resources"
	$dsoAppLockerRoot = "https://nopeblob.core.usgovcloudapi.net/nope/scripts/DSC/AppLocker"
	$azCopyDownloadUrl = "https://aka.ms/downloadazcopy-v10-windows"

	$dsoRoot = 'C:\nope\$SecDevOps'
	$geocodePath = "C:\ProgramData\nope\nopeWeb_Default"
	$dsoLocalResources = Join-Path $dsoRoot "Resources"
	$azCopyPath = Join-Path $dsoRoot "azcopy.exe"
	$policyPath = Join-Path $dsoRoot "Applocker-Global-pol.xml"

	$productKey2016 = Get-AutomationVariable -Name "Server2016Key"
	$productKey2022 = Get-AutomationVariable -Name "Server2022Key"
	$domainJoinUser = Get-AutomationVariable -Name "domainJoinSvc"
	$domainJoinPass = Get-AutomationVariable -Name "domainJoinSecret"
	$nopelaPass = Get-AutomationPSCredential -Name "$hostName-localadmin"


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
			ValueData = "https://wsusserver.com:8531"
			Force     = $true
		}

		Registry WSUSStatusServer
		{
			Ensure    = "Present"
			Key       = $registryPathWSUS
			ValueName = "WUStatusServer"
			ValueType = "String"
			ValueData = "https://wsusserver.com:8531"
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

		User nopela
		{
			Ensure                 = "Present"
			Disabled               = $false
			UserName               = "nopela"
			FullName               = "nopela"
			Password               = $nopelaPass
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
			DependsOn = "[Script]Net35Download"
		}

		WindowsFeatureSet DMZWebServer
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
			DependsOn = "[Script]Net35Download"
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

		Script IndexRedirectDownload
		{
			TestScript = {
				$indexPath = "C:\inetpub\wwwroot\index.htm"
				if ((Test-Path -Path $indexPath) -and ((Get-Content -Path $indexPath |
							Out-String -Stream) -like "*./nopeweb*"))
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
				(& $using:azCopyPath login --identity --output-level="essential") | Out-Null
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/nightlytestindex.htm" `
						$indexPath --overwrite=true --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
			}
			GetScript  = {
				@{ Result = ((Get-Content -Path "C:\inetpub\wwwroot\index.htm")) }
			}
			DependsOn  = "[Script]DownloadAzCopy"
		}

		Script Net48Download
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
				(& $using:azCopyPath login --identity --output-level="essential") | Out-Null
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/ndp48-x86-x64-allos-enu.exe" `
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
			DependsOn  = "[Script]DownloadAzCopy"
		}

		Script Net35Download
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
				(& $using:azCopyPath login --identity --output-level="essential") | Out-Null
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/microsoft-windows-netfx3-ondemand-package~31bf3856ad364e35~amd64~~.cab" `
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
			DependsOn  = "[Script]DownloadAzCopy"
		}

		Script MSOLEDBSQLDownload
		{
			TestScript = {
				Remove-Item "$using:dsoLocalResources\msoledbsql_18.6.5_x64_recommended.msi" `
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
				$msoledbsqlPath = Join-Path $using:dsoLocalResources "msoledbsql_18.6.5_x64_recommended.msi"
				(& $using:azCopyPath login --identity --output-level="essential") | Out-Null
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/msoledbsql_18.6.5_x64_recommended.msi" `
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
			DependsOn  = "[Script]DownloadAzCopy"
		}

		Script GeocodeDataDownload
		{
			TestScript = {
				$geocodeReferenceData = "FL_tiger.sqlite", "KS_tiger.sqlite", "TX_tiger.sqlite"
				$geocodeDifferenceData = (Get-ChildItem "$using:geocodePath\nopeData" -ErrorAction SilentlyContinue).Name
				$geocodeIsPresent = @(Compare-Object -ReferenceObject @($geocodeReferenceData | Select-Object) `
						-DifferenceObject @($geocodeDifferenceData | Select-Object)).Length -eq 0
				$geocodeIsPresent
			}
			SetScript  = {
				(& $using:azCopyPath login --identity --output-level="essential") | Out-Null
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
			DependsOn  = "[Script]DownloadAzCopy"
		}
		
		Script DomainJoin
		{
			Testscript = {
				if (((Get-WmiObject Win32_ComputerSystem).Domain | Out-String -Stream) -like '*nope' )
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				(Get-WmiObject -NameSpace "Root\Cimv2" -Class "Win32_ComputerSystem").JoinDomainOrWorkgroup("bamf.com", "$using:domainJoinPass", "$using:domainJoinUser", $null, 3)
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
			DependsOn  = "[User]nopela"
		}

		Script LocalAdministratorGroup
		{
			TestScript = {
				if ((Get-LocalGroupMember -Group "Administrators").Name -like "$using:hostName\nopela")
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				Add-LocalGroupMember -Group "Administrators" -Member 'nopela' -ErrorAction SilentlyContinue
			}
			GetScript  = {
				@{ Result = (Get-LocalGroupMember -Group "Administrators") }
			}
			DependsOn  = @(
				"[User]nopela"
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
			DependsOn  = "[WindowsFeatureSet]DMZWebServer"
		}

		Script CryptoWebServerStrict
		{
			TestScript = {
				#Count is 11 here instead of 10 as typical due to setup process requiring an additional cipher suite for nightly test systems. 
				if ((Get-TlsCipherSuite | Format-Table -HideTableHeaders).Count -eq 11)
				{
					$true 
				}
				else
				{
					$false 
				}
			}
			SetScript  = {
				# Disable Multi-Protocol Unified Hello
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
                
				# Disable PCT 1.0
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
                
				# Disable SSL 2.0 (PCI Compliance)
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
                
				# Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
                
				# Disable TLS 1.0 for client and server SCHANNEL communications
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
                
				# Add and Disable TLS 1.1 for client and server SCHANNEL communications
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
                
				# Add and Enable TLS 1.2 for client and server SCHANNEL communications
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
				New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
                
				# Re-create the ciphers key.
				New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null
                
				# Disable insecure/weak ciphers.
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
				Foreach ($insecureCipher in $insecureCiphers)
				{
					$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
					$key.SetValue('Enabled', 0, 'DWord')
					$key.close()
				}
    
				# Enable new secure ciphers.
				$secureCiphers = @(
					'AES 128/128',
					'AES 256/256'
				)
				Foreach ($secureCipher in $secureCiphers)
				{
					$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
					New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
					$key.close()
				}
                
				# Set hashes configuration.
				New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes' -Force | Out-Null
                
				$secureHashes = @(
					'MD5',
					'SHA',
					'SHA256',
					'SHA384',
					'SHA512'
				)
				Foreach ($secureHash in $secureHashes)
				{
					$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
					New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
					$key.close()
				}
                
				# Set KeyExchangeAlgorithms configuration.
				New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null
				$secureKeyExchangeAlgorithms = @(
					'Diffie-Hellman',
					'ECDH',
					'PKCS'
				)
				Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms)
				{
					$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
					New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
					$key.close()
				}
				# Configure longer DHE keys
				New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ServerMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null

				# Enable only Strict Web Server cipher suites
				$cipherSuitesOrder = @(
					'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
					'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
					'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
					'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
					'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
					'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
					'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
				) 
				$cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
				New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null
				New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
				New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
			}
			GetScript  = {
				@{ Result = (Get-TlsCipherSuite | Format-Table -HideTableHeaders | Out-String -Stream) }
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