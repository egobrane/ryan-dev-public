# This script allows you to set TLS restrictions based on potential exception profiles.
# None   = fully restricts to secure cipher suites and TLS 1.2
# TLS    = only restricts cipher suites
# Cipher = only restricts TLS protocols
# Both   = only sets secure hash algorithms and key exchange algorithms - for use in automation

param (
	[Parameter(Mandatory = $true)]
	[ValidateSet("None", "TLS", "Cipher", "Both")]
	[string]$cryptoExceptions = ""
)



# Set TLS restrictions
$schannelRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\'
$mpuhPath = Join-Path $schannelRegistryPath "\Protocols\Multi-Protocol Unified Hello"
$pct10Path = Join-Path $schannelRegistryPath "\Protocols\PCT 1.0"
$ssl20Path = Join-Path $schannelRegistryPath "\Protocols\SSL 2.0"
$ssl30Path = Join-Path $schannelRegistryPath "\Protocols\SSL 3.0"
$tls10Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.0"
$tls11Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.1"
$tls12Path = Join-Path $schannelRegistryPath "\Protocols\TLS 1.2"



#Disable Insecure Protocols
if ($cryptoExceptions -eq "Cipher" -or "None")
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