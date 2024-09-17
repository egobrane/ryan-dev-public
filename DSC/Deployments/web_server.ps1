Configuration dmz_web_server {



	#Import Modules for all necessary DSC resources - must be in Azure Automation
	Import-DscResource -ModuleName WebAdministrationDsc
	Import-DscResource -ModuleName PSDesiredStateConfiguration 
	Import-DscResource -ModuleName DSCR_PowerPlan
	Import-DscResource -ModuleName CertificateDsc


	$azureBlobUrl = "blob.core.usgovcloudapi.net"
	$azureStorageAccount = "egobranemisc"
	$azureStorageContainer = "cyberops"
	$azureStorageRoot = "https://$($azureStorageAccount).$($azureBlobUrl)/$($azureStorageContainer)/"
	$dsoStorageRoot = $azureStorageRoot + "scripts/DSC/Resources"
	$dsoAppLockerRoot = $azureStorageRoot + "scripts/DSC/AppLocker"
	$dsoUpdateRoot = $azureStorageRoot + "scripts/Update"
	$azCopyDownloadUrl = "https://aka.ms/downloadazcopy-v10-windows"

	$dsoRoot = 'C:\egobrane\$cyberops'
	$gpoType = "egobranecomdomain"
	$dsoLocalStorageRoot = Join-Path $dsoRoot "Resources"
	$azCopyPath = Join-Path $dsoRoot "azcopy.exe"

	$yearRange = Get-AutomationVariable -Name "egobraneComCertYearRange"
	$SSLThumbprint = Get-AutomationVariable -Name "$yearRange-egobranecom-thumbprint"
	$IKey = Get-AutomationVariable -Name "DuoIKey"
	$SKey = Get-AutomationVariable -Name "DuoSKey"
	$symlinkCred = Get-AutomationPSCredential -Name "dmz-share-svc"
	$egobraneComCert = Get-AutomationPSCredential -Name "$yearRange-egobranecom-cert"
	$ProductKey = Get-AutomationVariable -Name "Server2022Key"

	#Desc: DMZ Web Server DSC Configuration
	Node localhost {

		#Doc: Sets FIPS Algorithm registry policies.
		Registry FIPSAlgorithmPolicy
		{
			Ensure    = "Present"
			Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
			ValueName = "Enabled"
			ValueType = "Dword"
			ValueData = "1"
			Force     = $true
		}

		#Doc: Allows multiple RDP sessions per user.
		Registry TerminalServer
		{
			Ensure    = "Present"
			Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"
			ValueName = "fSingleSessionPerUser"
			ValueType = "Dword"
			ValueData = "0"
			Force     = $true
		}

		#Doc: Sets Power Plan to Balanced.
		cPowerPlan Balanced
		{
			Ensure = "Present"
			GUID   = "SCHEME_BALANCED"
			Name   = "Balanced"
			Active = $true
		}

		#Doc: Sets AC MonitorTimeOut to 0.
		cPowerPlanSetting MonitorTimeout
		{
			PlanGuid    = "SCHEME_BALANCED"
			SettingGuid = "VIDEOIDLE"
			Value       = 0
			AcDc        = "AC"
		}

		#Doc: Ensures egobraneWeb MapData directory is present.
		File MapData
		{
			Ensure          = "Present"
			Type            = "Directory"
			DestinationPath = "C:\ProgramData\egobrane\egobraneWeb_Default\MapData"
		}

		#Doc: Ensures presence of C:\egobrane\$cyberops.
		File cyberops
		{
			Ensure          = "Present"
			Type            = "Directory"
			DestinationPath = $dsoRoot
			Attributes      = "Hidden"
		}

		#Doc: Ensures presence of .NET Framework Windows Features.
		WindowsFeatureSet DMZNETFramework
		{
			Name   = @(
				"NET-Framework-Features"
				"NET-Framework-Core"
				"NET-Framework-45-Features"
				"NET-Framework-45-Core"
				"NET-Framework-45-ASPNET"
				"NET-WCF-Services45"
				"NET-WCF-TCP-PortSharing45"
			)
			Ensure = "Present"
		}

		#Doc: Ensures presence of Web Server Windows Features.
		WindowsFeatureSet DMZWebServer
		{
			Name   = @(
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
			Ensure = "Present"
		}

		#Doc: Ensures presence of Web Server Storage Service Windows Features.
		WindowsFeatureSet DMZStorageServices
		{
			Name   = @(
				"FileAndStorage-Services"
				"Storage-Services"
			)
			Ensure = "Present"
		}

		#Doc: Ensures IIS Full Logging is enabled.
		IisLogging FullLogs
		{
			LogPath         = "%SystemDrive%\inetpub\logs\LogFiles"
			Logflags        = @(
				"Date"
				"Time"
				"ClientIP"
				"UserName"
				"SiteName"
				"ComputerName"
				"ServerIP"
				"ServerPort"
				"Method"
				"UriStem"
				"UriQuery"
				"HttpStatus"
				"HttpSubStatus"
				"Win32Status"
				"BytesSent"
				"BytesRecv"
				"TimeTaken"
				"ProtocolVersion"
				"Host"
				"UserAgent"
				"Cookie"
				"Referer"
			)
			LogFormat       = "W3C" 
			LogPeriod       = "Daily"
			LogTargetW3C    = "File"
			LogCustomFields = DSC_LogCustomField
			{
				LogFieldName = "X-Forwarded-For"
				SourceName   = "X-Forwarded-For"
				SourceType   = "RequestHeader"
				Ensure       = "Present"
			}
			DependsOn       = "[WindowsFeatureSet]DMZWebServer"
		}

		#Doc: Ensures latest egobraneCOM wildcard certificate is bound to port 443.
		WebSite SSLBindings
		{
			Ensure      = "Present"
			Name        = "Default Web Site"
			DependsOn   = @(
				"[PfxImport]Staregobrane"
				"[WindowsFeatureSet]DMZWebServer"
			)
			BindingInfo = @(
				DSC_WebBindingInformation
				{
					Protocol              = "HTTPS"
					Port                  = "443"
					CertificateStoreName  = "MY"
					CertificateThumbprint = $SSLThumbprint
					IPAddress             = "*"
				}
				DSC_WebBindingInformation
				{
					Protocol  = "HTTP"
					Port      = "80"
					IpAddress = "*"
				}
			)
		}

		#Doc: Ensures presence of egobraneCOM wildcard certificate in local machine's personal store.
		PfxImport Staregobrane
		{
			Thumbprint   = $SSLThumbprint
			Path         = "$dsoLocalStorageRoot\STAR_egobrane_com_$yearRange.pfx"
			Location     = "LocalMachine"
			Store        = "My"
			Credential   = $egobraneComCert
			Ensure       = "Present"
			FriendlyName = "*.egobrane.com $yearRange"
			DependsOn    = "[Script]DownloadCert"
		}

		#Doc: Ensures AzCopy is located in C:\egobrane\$cyberops, and downloads latest from Microsoft if not.
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
			DependsOn  = "[File]cyberops"
		}

		#Doc: Ensures Az.Accounts, Az.KeyVault, and Az.Storage PowerShell modules are installed and present.
		Script DownloadAzModules
		{
			TestScript = {
				[System.Collections.ArrayList]$moduleList = (Get-InstalledModule Az* -ErrorAction SilentlyContinue).Name
				if ($moduleList -contains "Az.Accounts" -and $moduleList -contains "Az.KeyVault" -and $moduleList -contains "Az.Storage")
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript = {
				if (!(Get-PackageProvider))
				{
					$packageManagerSource = "https://www.powershellgallery.com/api/v2/package/PackageManagement/1.1.0.0"
					$packageManagerZipUrl = (Invoke-WebRequest -UseBasicParsing -Uri $packageManagerSource -MaximumRedirection 0 -ErrorAction SilentlyContinue).headers.location
					$packageManagerFile = Split-Path $packageManagerZipUrl -Leaf
					$packageManagerTargetPath = Join-Path $using:dsoRoot $packageManagerFile
					$packageManagerTargetDir = (Get-Module PackageManagement -listavailable | Where-Object {$_.Path -like "*Program Files*"} ) | Split-Path | Split-Path
					Invoke-WebRequest -UseBasicParsing -Uri $packageManagerZipUrl -OutFile $packageManagerTargetPath
					Rename-Item -Path $packageManagerTargetPath -NewName ($packageManagerTargetPath).Replace("nupkg", "zip")
					Expand-Archive -Path ($packageManagerTargetPath).Replace("nupkg", "zip") -DestinationPath (Join-Path $packageManagerTargetDir "1.1.0.0")
					Import-Module PackageManagement -Force
				}
				Install-PackageProvider -Name NuGet -Force
				Install-Module -Name Az.Accounts, Az.KeyVault, Az.Storage -Scope AllUsers -Force
			}
			GetScript = {
				@{ Result = (Get-InstalledModule Az* -ErrorAction SilentlyContinue).Name }
			}
		}

		#Doc: Ensures Microsoft Defender for Endpoint is onboarded and monitoring.
		Script GetDefenderStatus
        {
            TestScript = {
                if ((Get-MpComputerStatus).AMRunningMode -eq "Normal" -and `
                ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue).OnboardingState) -eq "1")
                {
                    $true
                } 
                else
                {
                    $false
                }
            }
            SetScript = {
                throw  "Error: MDE not responding or configured. Please investigate." 
            }
            GetScript = {
                @{Result = (Get-MpComputerStatus).AmRunningMode }
            }
        }

		#Doc: Ensures egobranela local admin user is present and initially set with randomly-generated complex password in Azure Automation.
		Script SetegobraneLAUser
		{
			TestScript = {
				if ([System.Collections.ArrayList](Get-LocalUser).Name -Contains "egobranela")
				{
					$true
				}
				else
				{
					$false
				} 		
			}
			SetScript = {
				do
				{
					Connect-AzAccount -Environment AzureUSGovernment -Scope Process -Identity
				} until (Get-AzTenant)
				New-LocalUser -Name "egobranela" -NoPassword -ErrorAction SilentlyContinue
				Set-LocalUser -Name "egobranela" -Password (Get-AzKeyVaultSecret -VaultName "dsc-config-vault" -Name ($env:COMPUTERNAME.Replace("_","-") + "-egobranela")).SecretValue
				Set-LocalUser -Name "egobranela" -PasswordNeverExpires $true
			}
			GetScript = {
				@{Result = (Get-LocalUser | Where-Object {$_.Name -eq "egobranela"} -ErrorAction SilentlyContinue) } 
			}
			DependsOn = @(
				"[Script]DownloadAzModules"
			)
		}

		#Doc: Ensures latest version of egobrane-user-monitor service is present, configured, and running.
		Script SetegobraneUserMonitor
		{
			TestScript = {
				do
				{
					Connect-AzAccount -Environment AzureUSGovernment -Scope Process -Identity | Out-Null
				} until (Get-AzTenant)
				$azureStorageCtx = New-AzStorageContext -StorageAccountName $using:azureStorageAccount
				$points = 0
				if (Get-Service -Name "egobrane-user-monitor" -ErrorAction SilentlyContinue)
				{
					$points++
				}
				$fileList = @(
					"egobrane-user-monitor.exe"
					"appsettings.json"
				)
				$presentFiles = (Get-ChildItem "$using:dsoRoot\egobrane-user-monitor" -ErrorAction SilentlyContinue).Name
				if ($presentFiles -contains "egobrane-user-monitor.exe" -and $presentFiles -contains "appsettings.json")
				{
					$points++
				}
				foreach ($file in $fileList)
				{
					$localVersion = (Get-Item "$using:dsoRoot\egobrane-user-monitor\$file" -ErrorAction SilentlyContinue).LastWriteTime
					$mostRecentVersion = (Get-AzStorageBlob -Context $azureStorageCtx -Container $using:azureStorageContainer -Blob "scripts/DSC/Resources/UserMonitor/$file").LastModified.LocalDateTime
					if ($localVersion -gt $mostRecentVersion)
					{
						$points++
					}
				}
				if ((Get-Service -Name "egobrane-user-monitor" -ErrorAction SilentlyContinue).Status -eq "Running")
				{
					$points++
				}
				if ($points -eq 5)
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript = {
				do
				{
					Connect-AzAccount -Environment AzureUSGovernment -Scope Process -Identity | Out-Null
				} until (Get-AzTenant)
				$azureStorageCtx = New-AzStorageContext -StorageAccountName $using:azureStorageAccount
				Remove-Item -Path "C:\egobrane\LogonAnnounce.exe", "C:\egobrane\LogoffAnnounce.exe" -Force -ErrorAction SilentlyContinue
				$fileList = @(
					"egobrane-user-monitor.exe"
					"appsettings.json"
				)
				$presentFiles = (Get-ChildItem "$using:dsoRoot\egobrane-user-monitor" -ErrorAction SilentlyContinue).Name
				if ($presentFiles -contains "egobrane-user-monitor.exe" -and $presentFiles -contains "appsettings.json")
				{
					foreach ($file in $fileList)
					{
						$localVersion = (Get-Item "$using:dsoRoot\egobrane-user-monitor\$file" -ErrorAction SilentlyContinue).LastWriteTime
						$mostRecentVersion = (Get-AzStorageBlob -Context $azureStorageCtx -Container $using:azureStorageContainer -Blob "scripts/DSC/Resources/UserMonitor/$file").LastModified.LocalDateTime
						if ($mostRecentVersion -gt $localVersion)
						{
							sc.exe stop "egobrane-user-monitor"
							$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/UserMonitor/$file" `
							"$using:dsoRoot\egobrane-user-monitor\$file" --output-level="essential") | Out-String
							if($LASTEXITCODE -ne 0)
							{
								throw (("Copy error. $result"))
							}
							sc.exe start "egobrane-user-monitor"
						}
					}
				}
				else
				{
					$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/UserMonitor/egobrane-user-monitor.exe" `
					"$using:dsoRoot\egobrane-user-monitor\egobrane-user-monitor.exe" --output-level="essential") | Out-String
					if($LASTEXITCODE -ne 0)
					{
						throw (("Copy error. $result"))
					}
					$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/UserMonitor/appsettings.json" `
					"$using:dsoRoot\egobrane-user-monitor\appsettings.json" --output-level="essential") | Out-String
					if($LASTEXITCODE -ne 0)
					{
						throw (("Copy error. $result"))
					}
				}
				if (!(Get-Service -Name "egobrane-user-monitor" -ErrorAction SilentlyContinue))
				{
					sc.exe create "egobrane-user-monitor" binPath="$using:dsoRoot\egobrane-user-monitor\egobrane-user-monitor.exe" start=auto
				}
				if ((Get-Service -Name "egobrane-user-monitor" -ErrorAction SilentlyContinue).Status -ne "Running")
				{
					sc.exe start "egobrane-user-monitor"
				}
			}
			GetScript = {
				@{Result = (Get-Service -Name "egobrane-user-monitor" -ErrorAction)}
			}
			DependsOn  = @(
				"[Script]SetAzCopyVariables"
				"[Script]DownloadAzModules"
			)
		}

		#Doc: Ensures additional local administrator users are present if required.
		Script SetAdditionalLAUser
		{
			TestScript = {
				do
				{
					Connect-AzAccount -Environment AzureUSGovernment -Scope Process -Identity
				} until (Get-AzTenant)
				if (Get-AzKeyVaultSecret -VaultName "dsc-config-vault" -name ($env:COMPUTERNAME.Replace("_","-") + "-userla"))
				{
					$users = @(Get-AzKeyVaultSecret -VaultName "dsc-config-vault" -name ($env:COMPUTERNAME.Replace("_","-") + "-userla") -AsPlainText).Split(',')
					foreach ($user in $users)
					{
						if ([System.Collections.ArrayList](Get-LocalUser).Name -Contains $user)
						{
							continue
						}
						else
						{
							return $false
						}
					}
				}
				$true
			}
			SetScript = {
				$passwordScript = {
					function randDouble
					{
						$i = 0;
						$flag = $true;
						$seedString = "";
						[Byte[]]$randomByte = 1..1;
						$gen = New-Object System.Security.Cryptography.RNGCryptoServiceProvider;
						while($flag)
						{
							$gen.GetBytes($randomByte);
							$rndNumber = [System.Convert]::ToInt32($randomByte[0]);
							if($rndNumber -eq 0) {continue;}
							$seedString = $seedString + $rndNumber;
							$i++;
							if($i -gt 2) {$flag = $false;} #3 1-255 strings combined.
						}
						$rand = New-Object -TypeName System.Random -ArgumentList $seedString;
						return $rand.NextDouble();
					}
								
					function randInt
					{
						param(
						[int]$lBound = 0,
						[int]$uBound = [Int32]::MaxValue
						)
						$rndDbl = randDouble;
						$lBoundDbl = [System.Convert]::ToDouble($lBound);
						$uBoundDbl = [System.Convert]::ToDouble($uBound);
						return [System.Convert]::ToInt32(($uBoundDbl - $lBoundDbl) * $rndDbl + $lBoundDbl);
					}
								
					function get-password
					{
						param(
						[int]$len = 25,
						[bool]$specials = $true
						)
								
						$lowerCharsOrg = "abdeghjqrty";#"abcdefghijkmnopqrstuvwxyz";
						$upperCharsOrg = "ABCDEFGHJKMNPQRTWXY";#"ABCDEFGHJKLMNPQRSTUVWXYZ"
						$numbersOrg = "2346789";#"23456789"
						$specialCharsOrg = "!@#$%^&*~";
						$lowerChars = $lowerCharsOrg;
						$upperChars = $upperCharsOrg;
						$numbers = $numbersOrg;
						$specialChars = $specialCharsOrg;
						$lenOrg = $len;
								
						$maxSet = 3;
						$maxSubLen = 25;
								
						if($specials -eq $false)
						{
							$specialChars = "";
							$maxSet = 2;
							$maxSubLen = 20;
						}
						$maxSubLenOrg = $maxSubLen;
								
						$output = "";
						while($output.Length -lt $lenOrg)
						{
							$maxSubLen = [Math]::Min($len, $maxSubLen);
							$subOutput = "";
							$lastSetI = 99;
							$lastChar = "";
							while($subOutput.Length -lt $maxSubLen)
							{
								$setI = randInt 0 $maxSet;
								if($setI -eq $lastSetI) {continue;}
								switch($setI)
								{
									0 {$set = $lowerChars;}
									1 {$set = $upperChars;}
									2 {$set = $numbers;}
									default {$set = $specialChars;}
								}
								$setLen = $set.Length - 1;
								if($setLen -lt 1)
								{
									$lastSetI = $setI;
									continue;
								}
								$i = randInt 0 $setLen;
								$char = $set.Substring($i, 1);
								if($subOutput.Contains($char)) #char already used.
								{
									switch($setI)
									{
										0 {$lowerChars = $lowerChars.Replace($char, "");}
										1 {$upperChars = $upperChars.Replace($char, "");}
										2 {$numbers = $numbers.Replace($char, "");}
										default {$specialChars = $specialChars.Replace($char, "");}
									}
									continue;
								}
								if($i -lt $setLen -and $($lastChar -eq $set.Substring(($i + 1), 1))) {continue;} #char not at set end and sequential.
								if($i -gt 0 -and $($lastChar -eq $set.Substring(($i - 1), 1))) {continue;} #char not at set beginning and sequential.
								$lastSetI = $setI;
								$lastChar = $char;
								$subOutput = $subOutput + $char;
							}
							$output = $output + $subOutput;
							$len = $len - $subOutput.Length;
							$lowerChars = $lowerCharsOrg;
							$upperChars = $upperCharsOrg;
							$numbers = $numbersOrg;
							$specialChars = $specialCharsOrg;
							$maxSubLen = $maxSubLenOrg;
						}
						return $output;
					}
					return get-password
				}

				Connect-AzAccount -Environment AzureUSGovernment -Scope Process -Identity
				$users = @(Get-AzKeyVaultSecret -VaultName "dsc-config-vault" -name ($env:COMPUTERNAME.Replace("_","-") + "-userla") -AsPlainText).Split(',')
				foreach ($user in $users)
				{
					if ([System.Collections.ArrayList](Get-LocalUser).Name -notcontains $user)
					{
						$securePassword = $passwordScript.Invoke() | ConvertTo-SecureString -AsPlainText -Force
						New-LocalUser -Name $user -Password $securePassword -ErrorAction SilentlyContinue
						Set-LocalUser -Name $user -PasswordNeverExpires $true
					}
				}
			}
			GetScript = {
				@{Result = (Get-LocalUser) } 
			}
			DependsOn = @(
				"[Script]DownloadAzModules"
			)
		}

		#Doc: Ensures AzCopy is set to Auto-Login with Machine Identity authentication for copying from Azure Storage.
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

		#Doc: Ensures C:\egobrane\$cyberops and all child objects only allows Read and Execute access for all users other than SYSTEM.
		Script SetcyberopsPermissions
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
			DependsOn  = "[File]cyberops"
		}

		#Doc: Ensures egobrane DSC Monitor scheduled task is present to monitor event logs for frozen DSC automation tasks and force them to restart if necessary. 
		Script SetDscMonitorScheduledTask
		{
			TestScript = {
				if ((Get-ScheduledTask -TaskName "egobrane DSC Monitor" -ErrorAction SilentlyContinue).TaskName -eq "egobrane DSC Monitor")
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript = {
				$name = "egobrane DSC Monitor"
				$desc = "This task monitors the LCM to check if it is stuck in a consistency check state, and corrects it if so."
				$class = cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
				$trigger = $class | New-CimInstance -ClientOnly
				$trigger.Enabled = $true
				$trigger.Subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-DSC/Operational"><Select Path="Microsoft-Windows-DSC/Operational">*[System[(EventID=4344) and TimeCreated[timediff(@SystemTime) &lt;= 3600000]]]</Select></Query></QueryList>'
				$actionParameters = @{
					Execute = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
					Argument = ' -Command "Stop-Process -Name WmiPrvSe -Force"'
				}
				$action = New-ScheduledTaskAction @actionParameters
				$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 23) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
				Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $name -Description $desc -User "NT AUTHORITY\SYSTEM" -Settings $settings -Force
			}
			GetScript = {
				@{ Result = (Get-ScheduledTask -TaskName "egobrane DSC Monitor" -ErrorAction SilentlyContinue | Where-Object {$_.TaskName -eq "egobrane DSC Monitor"}) }
			}
		}

		#Doc: Ensures Local State Configuration Manager is set to Pull configurations from Azure Automation, ApplyAndAutoCorrect configurations, and auto-correct itself if desired state is not present.
		Script SetDscParams
		{
			TestScript = {
				if (((Get-DscLocalConfigurationManager).RefreshMode -ne "Pull") -or ((Get-DscLocalConfigurationManager).ConfigurationMode -ne "ApplyAndAutoCorrect"))
				{
					$false
				}
				else
				{
					$true
				} 
				
			}
			SetScript = {
				Set-Content -Path "$using:dsoRoot\LCMfix.ps1" -Value "[DSCLocalConfigurationManager()]
				configuration LCMConfig
				{
					Node localhost
					{
						Settings
						{
							RefreshMode = 'Pull'
							ConfigurationMode = 'ApplyAndAutoCorrect'
						}
						ConfigurationRepositoryWeb AzureAutomationStateConfiguration
						{
							ServerUrl = 'https://egobrane.agentsvc.usge.azure-automation.us/accounts/egobrane'
						}
						ResourceRepositoryWeb AzureAutomationStateConfiguration
						{
							ServerUrl = 'https://egobrane.agentsvc.usge.azure-automation.us/accounts/egobrane'
						}
						ReportServerWeb AzureAutomationStateConfiguration
						{
							ServerUrl = 'https://egobrane.agentsvc.usge.azure-automation.us/accounts/egobrane'
						}
					}
				}
				
				LCMConfig -Output C:\Temp\LCMfix
				" 
					
				Powershell -ExecutionPolicy Bypass "$using:dsoRoot\LCMfix.ps1"
				Set-DscLocalConfigurationManager -Path "C:\Temp\LCMfix\" -Force
				Remove-Item -Path "$using:dsoRoot\LCMfix.ps1","C:\Temp\LCMfix\" -Recurse -Force -ErrorAction SilentlyContinue
			}
			GetScript = {
				@{Result = (Get-DscLocalConfigurationManager)}
			}
		}

		#Doc: Ensures Hidden Files and File Extensions are enabled in File Explorer options for all current users and future users.
		Script SetFolderOptions
		{
			TestScript = {
				New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
				$profileSIDs = @((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.ProfileImagePath -like "C:\Users\*" -and $_.ProfileImagePath -notlike "C:\Users\default*"}).PSChildName)
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
						[gc]::collect()
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
			SetScript = {
				Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt -Name "DefaultValue" -Value 0 -Force -ErrorAction SilentlyContinue
				New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
				$profileSIDs = @((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.ProfileImagePath -like "C:\Users\*" -and $_.ProfileImagePath -notlike "C:\Users\default*"}).PSChildName)
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
						[gc]::collect()
						& reg.exe unload "HKLM\TempHive_$profileSID"
					}
				}
				Remove-PSDrive -Name HKU
			}
			GetScript = {
				@{ Result = (Write-Host "Registry check") }
			}
		}
		
		#Doc: Ensures Windows is activated with an applicable product key.
		Script WindowsProductKey
		{
			TestScript = {
				$ProductKeyExpression = $using:ProductKey
				$PartialProductKey = $ProductKeyExpression.SubString($ProductKeyExpression.length - 5, 5)
				if ((Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object { $_.PartialProductKey -ne $null } |
						Select-Object -Property PartialProductKey | Out-String -Stream) -like "*$PartialProductKey*")
				{
					$true
				}
				else 
				{
					$false
				}
			}
			SetScript  = {
				$Slmgr = 'C:\Windows\System32\slmgr.vbs'
				$Cscript = 'C:\Windows\System32\cscript.exe'
				Start-Process -FilePath $Cscript -ArgumentList ($Slmgr, '-ipk', $using:ProductKey) | Out-Null
				Start-Process -FilePath $Cscript -ArgumentList ($Slmgr, '-ato')
			}
			GetScript  = {
				@{ Result = ((Get-WmiObject -query 'select * from SoftwareLicensingService').OA3xOriginalProductKey) }
			}
		}

		#Doc: Ensures Duo Authentication for Windows MFA is installed and registered to the egobrane environment.
		Script DuoInstall
		{
			TestScript = {
				$DuoInstall = "Duo Authentication for Windows Logon x64"
				$Installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
					Where-Object { $_.DisplayName -eq $DuoInstall }) -ne $null
				Remove-Item "$using:dsoRoot\duo-installer.exe" -Force -Confirm -ErrorAction SilentlyContinue
				if (-Not $Installed)
				{
					$false
				}
				else 
				{
					$true
				}
			}
			SetScript  = {
				$duoPath = Join-Path $using:dsoLocalStorageRoot "duo-installer.exe"
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
			)
		}

		#Doc: Downloads latest egobraneCOM wildcard certificate, based on date parameters entered on compilation.
		Script DownloadCert
		{
			TestScript = {
				Remove-Item "$using:dsoLocalStorageRoot\STAR_egobrane_com_$using:yearRange.pfx" -Force -Confirm -ErrorAction SilentlyContinue
				if (Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.FriendlyName -like "*$using:yearRange*" })
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript  = {
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/Certs/STAR_egobrane_com_$using:yearRange.pfx" `
						"$using:dsoLocalStorageRoot\STAR_egobrane_com_$using:yearRange.pfx" --output-level="essential") | Out-String
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

		#Doc: Ensures egobrane.com website root redirect is present.
		Script DownloadRedirect
		{
			TestScript = {
				$indexPath = "C:\inetpub\wwwroot\index.htm"
				if ((Test-Path -Path $indexPath) -and ((Get-Content -Path $indexPath |
							Out-String -Stream) -like "*www.egobrane*"))
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
				Get-ChildItem $indexPath -Exclude "web.config" | Remove-Item -Force -Confirm -ErrorAction SilentlyContinue
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/Redirects/dmzindex.htm" `
						$indexPath --overwrite=true --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}
			}
			GetScript  = {
				@{ Result = ('True' -in ((Get-Content -Path "C:\inetpub\wwwroot\index.htm" | Out-String -Stream) -like "*www.egobrane")) }
			}
			DependsOn  = @(
				"[Script]SetAzCopyVariables"
				"[WindowsFeatureSet]DMZWebServer"
			)
		}

		#Doc: Ensures "egobrane Updates" scheduled task for deployment of third-party application updates is configured.
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
		
		#Doc: Ensures Windows Firewall rules for Remote Desktop are enabled.
		Script SetRDPFirewall
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

		#Doc: Ensures RDP is enabled via registry keys 'fDenyTSConnections' 0 and 'UsersAuthentication' 1.
		Script SetRDPRegistry
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

		#Doc: Ensures Network Discovery firewall rules are disabled.
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
				@{ Result = (Get-NetFirewallRule -DisplayGroup "Network Discovery") }
			}
		}

		#Doc: Ensures TimeZone is set to 'Eastern Standard Time'.
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

		#Doc: Ensures PowerShell Execution Policy is set to "RemoteSigned" for LocalMachine and CurrentUser scopes.
		Script SetExecutionPolicy
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

		#Doc: Ensures local Administrators group contains egobranela and DMZ Administrators role.
		Script SetLocalAdminDMZRole
		{
			TestScript = {
				if ((Get-LocalGroupMember -Group "Administrators" | Out-String -Stream) -like '*egobraneCOM\$8G4000-3S2D3LMFN9RL*' `
						-and (Get-LocalGroupMember -Group "Administrators" | Out-String -Stream) -like '*egobranela*')
				{
					$true 
				}
				else
				{
					$false 
				}
			}
			SetScript  = {
				Add-LocalGroupMember -Group "Administrators" -Member 'egobraneCOM\$8G4000-3S2D3LMFN9RL', 'egobranela' -ErrorAction SilentlyContinue
			}
			GetScript  = {
				@{ Result = (Get-LocalGroupMember -Group "Administrators" | Out-String -Stream) }
			}
			DependsOn  = @(
				"[Script]SetegobraneLAUser"
			)
		}
        
		#Doc: Ensures GeocodeData symbolic link is present and pointing to \\dmz-sql\GeocodeData\.
		Script SetSymbolicGeocode
		{
			TestScript           = {
				if (Test-Path -Path "C:\ProgramData\egobrane\egobraneWeb_Default\GeocodeData")
				{
					$true 
				}
				else
				{
					$false 
				}                    
			}            
			SetScript            = {
				New-Item -ItemType SymbolicLink -Path "C:\ProgramData\egobrane\egobraneWeb_Default\GeocodeData\" -Target "\\dmz-sql\GeocodeData\"
			}
			GetScript            = {
				@{ Result = (Get-ChildItem "C:\ProgramData\egobrane\egobraneWeb_Default\") }
			}
			PsDscRunAsCredential = $symlinkCred
			DependsOn            = @(
				"[Script]MapData"
			)
		}

		#Doc: Ensures MapData symbolic link is present and pointing to \\dmz-sql\MapData\Vector20220518\.
		Script MapData
		{
			TestScript           = {
				if (Test-Path -Path "C:\ProgramData\egobrane\egobraneWeb_Default\MapData\Vector20220518\")
				{
					$true 
				}
				else
				{
					$false 
				}
			}
			SetScript            = {
				New-Item -ItemType SymbolicLink -Path "C:\ProgramData\egobrane\egobraneWeb_Default\MapData\Vector20220518\" -Target "\\dmz-sql\MapData\Vector20220518\"
			}
			GetScript            = {
				@{ Result = (Get-ChildItem "C:\ProgramData\egobrane\egobraneWeb_Default\") }
			}
			PsDscRunAsCredential = $symlinkCred
			DependsOn            = @(
				"[File]MapData"
			)
		}

		#Doc: Ensures X-Powered-By header is not present in IIS.
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

		#Doc: Ensures time.windows.com is set as NTP server target.
		Script SetNTPConfig
		{
			TestScript = {
				$dateTimeReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers"
				$w32Reg = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
				$NTPServers = @((Get-Item -Path $dateTimeReg -ErrorAction SilentlyContinue).Property | Sort-Object)
				$defaultTargetPriority = (Get-ItemProperty -Path $dateTimeReg -Name $NTPServers[0] -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $NTPServers[0])
				$defaultTarget = (Get-ItemProperty -Path $dateTimeReg -Name $defaultTargetPriority -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $defaultTargetPriority)
				$NTPType = (Get-ItemProperty -Path $w32Reg -Name Type | Select-Object -ExpandProperty Type)
				$NTPServerProperty = (Get-ItemProperty -Path $w32Reg -Name NtpServer | Select-Object -ExpandProperty NtpServer)
				
				if ($defaultTarget -eq "time.windows.com" -and $NTPType -eq "NTP" -and $NTPServerProperty -eq "time.windows.com")
				{
					$true
				}
				else
				{
					$false
				} 
			}
			SetScript = {
				w32tm /config /syncfromflags:manual /manualpeerlist:time.windows.com
				w32tm /config /update
				w32tm /resync 
				
			}
			GetScript = {
				@{ Result = (w32tm /query /configuration)} 
			}
		}

		#Doc: Ensures IIS Default Web Site is configured for Strict Transport Security, including all subdomains.
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
			DependsOn  = "[WindowsFeatureSet]DMZWebServer"
		}

		#Doc: Ensures local built-in "Administrator" account is disabled.
		Script SetLocalAdministratorDisabled
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
        
		#Doc: Sets TLS 1.2 restrictions, secure algorithms, secure cipher suites and disables insecure versions.
		Script CryptoWebServerStrict
		{
			TestScript = {
				do
				{
					Connect-AzAccount -Environment AzureUSGovernment -Scope Process -Identity
				} until (Get-AzContext)
				if ($cryptoExceptions = Get-AzKeyVaultSecret -VaultName "dsc-config-vault" -Name ($env:COMPUTERNAME.Replace("_","-") + "-CryptoExceptions") -AsPlainText -ErrorAction SilentlyContinue){}
				else
				{
					$cryptoExceptions = "None"
				}
				switch ( $cryptoExceptions )
				{
					"TLS"
					{
						$intendedCipherArray = @(
							'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
							'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
							'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
							'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
							'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
							'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
						)
						$currentCipherArray = (Get-TlsCipherSuite | Sort-Object -Property BasecipherSuite -Descending).Name
						$cipherMatch = @(Compare-Object -ReferenceObject @($intendedCipherArray) `
								-DifferenceObject @($currentCipherArray)).Length -eq 0
						$cipherMatch
					}

					"Ciphers"
					{
						$schannelRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\'
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
						$currentTLSArray = Get-ItemPropertyValue -Path $schannelRegistryPath\Protocols\*\* -Name Enabled -ErrorAction SilentlyContinue
						$tlsMatch = @(Compare-Object -ReferenceObject @($intendedTLSArray) `
								-DifferenceObject @($currentTLSArray)).Length -eq 0
						$tlsMatch
					}

					"None"
					{
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

					"Both"
					{
						$true
					}
				}
			}
			SetScript  = {
				do
				{
					Connect-AzAccount -Environment AzureUSGovernment -Scope Process -Identity
				} until (Get-AzContext)
				if ($cryptoExceptions = Get-AzKeyVaultSecret -VaultName "dsc-config-vault" -Name ($env:COMPUTERNAME.Replace("_","-") + "-CryptoExceptions") -AsPlainText -ErrorAction SilentlyContinue){}
				else
				{
					$cryptoExceptions = "None"
				}

				$schannelRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\'
				$mpuhPath = Join-Path $schannelRegistryPath "\Protocols\Multi-Protocol Unified Hello"
				$pct10Path = Join-Path $schannelRegistryPath "\Protocols\PCT 1.0"
				$ssl20Path = Join-Path $schannelRegistryPath "\Protocols\SSL 2.0"
				$ssl30Path = Join-Path $schannelRegistryPath "\Protocols\SSL 3.0"
				$tls10Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.0"
				$tls11Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.1"
				$tls12Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.2"

				#Disable Insecure Protocols
				if ($cryptoExceptions -eq "Ciphers" -or "None")
				{
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
				}

				# Disable Insecure Ciphers
				if ($cryptoExceptions -eq "TLS" -or "None")
				{
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
				if ($cryptoExceptions -eq "TLS" -or "None")
				{
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
			}
			GetScript  = {
				@{ Result = ([Net.ServicePointManager]::SecurityProtocol) }
			}
			DependsOn = @(
				"[Script]DownloadAzModules"
			)
		}
		
		#Doc: Ensures Application Identity Service is running for AppLocker.
		Service AppIDsvc
		{
			Name           = "AppIDSvc"
			State          = "Running"
			BuiltinAccount = "LocalService"
			DependsOn      = @(
				"[Script]SetAppLocker"
			)
		}

		#Doc: Ensures Application Identity Service is set to auto-start, from registry key.
		Registry AutoStartupAppID
		{
			Ensure    = "Present"
			Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc"
			ValueName = "Start"
			ValueType = "Dword"
			ValueData = "2"
			Force     = $true
		}

		#Doc: Ensures latest relevant AppLocker policy is downloaded from Azure Storage and ensures it remains applied.
		Script SetAppLocker
		{
			TestScript = {
				$false
			}
			SetScript  = {
				do
				{
					Connect-AzAccount -Environment AzureUSGovernment -Scope Process -Identity
				} until (Get-AzContext)
				if ($appLockerMode = Get-AzKeyVaultSecret -VaultName "dsc-config-vault" -Name ($env:COMPUTERNAME.Replace("_","-") + "-applocker") -AsPlainText -ErrorAction SilentlyContinue )
				{
					if ($appLockerMode -eq "Enforce")
					{
						$targetPolicy = "$using:dsoAppLockerRoot/Applocker-Global-Enforce.xml"
						$policyPath = "$using:dsoRoot\Applocker-Global-Enforce.xml"
					}
					elseif ($appLockerMode -eq "Developer")
					{
						$targetPolicy = "$using:dsoAppLockerRoot/Applocker-Global-Dev.xml"
						$policyPath = "$using:dsoRoot\Applocker-Global-Dev.xml"
					}
					elseif ($appLockerMode -eq "Server")
					{
						$targetPolicy = "$using:dsoAppLockerRoot/Applocker-Server.xml"
						$policyPath = "$using:dsoRoot\Applocker-Server.xml"
					}
					else
					{
						$targetPolicy = "$using:dsoAppLockerRoot/Applocker-Global-pol.xml"
						$policyPath = "$using:dsoRoot\Applocker-Global-pol.xml"
					}
				}
				else
				{
					$targetPolicy = "$using:dsoAppLockerRoot/Applocker-Global-pol.xml"
					$policyPath = "$using:dsoRoot\Applocker-Global-pol.xml"
				}
				$result = (& $using:azCopyPath copy $targetPolicy "$policyPath" --overwrite=ifSourceNewer --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					$result = (& $using:azCopyPath copy $targetPolicy "$policyPath" --overwrite=ifSourceNewer --output-level="essential") | Out-String
					if($LASTEXITCODE -ne 0)
					{
						throw (("Copy error. $result"))
					}
				}
				Get-ChildItem $using:dsoRoot | Where-Object {$_.Name -like "Applocker*xml" -and $_.Name -ne ($policyPath | Split-Path -Leaf)} | Remove-Item -Force 
				Set-AppLockerPolicy -XmlPolicy "$policyPath"
			}
			GetScript  = {
				@{ Result = (Get-ChildItem "$dsoRoot" | Where-Object {$_.Name -like "Applocker*xml"}) } 
			}
			DependsOn  = @(
				"[Script]SetAzCopyVariables"
				"[Script]DownloadAzModules"
			)
		}

		#Doc: Downloads latest compiled aggregated copy of applicable GPOs as a .PolicyRules file and imports them locally, if node is not on egobraneNET domain.
		Script SetGPOs
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