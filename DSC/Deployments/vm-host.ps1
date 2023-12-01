Configuration VMHost {

	param (
		[Parameter(Mandatory = $true)]
		[string]$hostName = "localhost"
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration

	$dsoStorageRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/Resources"
	$dsoAppLockerRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/AppLocker"
	$azCopyDownloadUrl = "https://aka.ms/downloadazcopy-v10-windows"

	$dsoRoot = 'C:\egobrane\$DevSecOps'
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
					'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
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
	}
}