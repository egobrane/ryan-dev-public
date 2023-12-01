Configuration Workstationv2 {

	param (
		[Alias("Crypto Exception Profile")]
		[ValidateSet("None", "TLS", "Ciphers", "Both")]
		[Parameter(Mandatory = $true)]
		[string]$cryptoExceptions = ("None", "TLS", "Ciphers", "Both"),

		[Parameter(Mandatory = $true)]
		[string]$hostName = "localhost"		
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration

	$dsoStorageRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/Resources"
	$dsoAppLockerRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/AppLocker"
	$azCopyDownloadUrl = "https://aka.ms/downloadazcopy-v10-windows"

	$dsoRoot = 'C:\egobrane\$DevSecOps'
	$dsoLocalStorageRoot = 'C:\egobrane\$DevSecOps\Resources'
	$gpoType = "egobranecomdomain"
	$azCopyPath = Join-Path $dsoRoot "azcopy.exe"
	$policyPath = Join-Path $dsoRoot "Applocker-Global-pol.xml"


	Node $hostName {


		File DevSecOps
		{
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = $dsoRoot
			Attributes = "Hidden"
		}

		File egobrane
		{
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = "C:\egobrane"
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
			SetScript = {
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
			GetScript = {
				@{ Result = (Test-Path $using:azCopyPath) }
			}
			DependsOn = "[File]DevSecOps"
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
			SetScript = {
				Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
				Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
			}
			GetScript = {
				@{ Result = (Get-ExecutionPolicy) }
			}
		}

		Script CryptoWebServerStrict
		{
			TestScript = {
				if ((Get-TlsCipherSuite | Format-Table -HideTableHeaders).Count -eq 10)
				{
					$true
				}
				else
				{
					$false
				}
			}
			SetScript = {
				$schannelRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\'
				$mpuhPath = Join-Path $schannelRegistryPath "\Protocols\Multi-Protocol Unified Hello"
				$pct10Path = Join-Path $schannelRegistryPath "\Protocols\PCT 1.0"
				$ssl20Path = Join-Path $schannelRegistryPath "\Protocols\SSL 2.0"
				$ssl30Path = Join-Path $schannelRegistryPath "\Protocols\SSL 3.0"
				$tls10Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.0"
				$tls11Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.1"
				$tls12Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.2"

				$insecureProtocolPathArray = @(
					$mpuhPath,
					$pct10Path,
					$ssl20Path,
					$ssl30Path,
					$tls10Path,
					$tls11Path
				)

				#Disable Insecure Protocols
				foreach ($insecureProtocol in $insecureProtocolPathArray) {
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
				foreach ($secureProtocol in $secureProtocolArray) {
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

				foreach ($insecureCipher in $insecureCiphers) {
					$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
					$key.SetValue('Enabled', 0, 'Dword')
					$key.Close()
				}

				# Enable Secure Ciphers
				$secureCiphers = @(
					'AES 128/128',
					'AES 256/256'
				)

				foreach ($secureCipher in $secureCiphers) {
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

				foreach ($secureHash in $secureHashes) {
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

				foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
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
			GetScript = {
				@{ Result = (Get-TlsCipherSuite | Format-Table -HideTableHeaders | Out-String -Stream) }
			}
		}

		#Begin AppLocker Configuration Block
		Service AppIDsvc
		{
			Name = "AppIDSvc"
			State = "Running"
			BuiltInAccount = "LocalService"
			DependsOn = @(
				"[Script]PolicyUpdate"
			)
		}

		Registry AutoStartupAppID
		{
			Ensure = "Present"
			Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc"
			ValueName = "Start"
			ValueType = "Dword"
			ValueData = "2"
			Force = $true
		}

		#Check if remote policy has changed and downloads latest policy if so
		Script PolicyUpdate
		{
			TestScript = {
				$false
			}
			SetScript = {
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
			GetScript = {
				@{
					GetScript = $GetScript
					SetScript = $TestScript
					TestScript = $TestScript
					Result = (Get-Content "$using:policyPath")
				}
			}
			DependsOn = "[Script]SetAzCopyAutoLoginVariable"
		}


		# Begin GPO Section
		Script GPOSettings
		{
			TestScript = {
				$false
			}
			SetScript = {
				$lgpoPath = Join-Path $using:dsoLocalStorageRoot "\LGPO.exe"
				$gpoPath = Join-Path $using:dsoLocalStorageRoot "\$using:gpoType.PolicyRules"
				
				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/LGPO.exe" `
					$lgpoPath --overwrite=ifSourceNewer --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}

				$result = (& $using:azCopyPath copy "$using:dsoStorageRoot/$using:gpoType.PolicyRules" `
					$gpoPath --overwrite=ifSourceNewer --output-level="essential") | Out-String
				if($LASTEXITCODE -ne 0)
				{
					throw (("Copy error. $result"))
				}

				(& $lgpoPath /q /p $gpoPath)
			}
			GetScript = {
				@{ Result = (Get-Item $gpoPath -ErrorAction SilentlyContinue)}
			}
		}
	}
}