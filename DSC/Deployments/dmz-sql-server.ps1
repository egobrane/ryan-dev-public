Configuration DmzSQLServer {

#   This script has the following known issues
#1. Many variables are wrong. This is an obscured public copy of my private DSC script. 
                                                                                                                                                                                        

    #Update ODJ URI with Blob SAS URI for this instance
    param (
        [Parameter(Mandatory=$true)]
        [string]$HostName,

        [Parameter(Mandatory=$true)]
        [string]$odjUri
    )
    
    #Import Modules for all necessary DSC resources - must be in Azure Automation
    Import-DscResource -ModuleName ComputerManagementDSC
    Import-DscResource -ModuleName DSCR_MSLicense
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName DSCR_PowerPlan
    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    $DMZlaPass = Get-AutomationPSCredential -Name "$HostName-egobranela"
    $resourceUri = "https://egobrane.com/resource"


    #Specify node assignment
    Node $HostName {


        #Registry Resources
        Registry FIPSAlgorithmPolicy
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
            ValueName = "Enabled"
            ValueType = "Dword"
            ValueData = "1"
            Force = $true
        }

        Registry TerminalServer
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"
            ValueName = "fSingleSessionPerUser"
            ValueType = "Dword"
            ValueData = "0"
            Force = $true
        }


        #Remote Desktop Resources
        RemoteDesktopAdmin RemoteDesktopSettings
        {
            IsSingleInstance = "Yes"
            Ensure = "Present"
            UserAuthentication = "Secure"
        }


        #Timezone Resources
        TimeZone EasternTime
        {
            IsSingleInstance = "Yes"
            TimeZone = "Eastern Standard Time"
        } 


        #PowerPlan Resources
        cPowerPlan Balanced
        {
            Ensure = "Present"
            GUID = "SCHEME_BALANCED"
            Name = "Balanced"
            Active = $true
        }

        cPowerPlanSetting MonitorTimeout
        {
            PlanGuid = "SCHEME_BALANCED"
            SettingGuid = "VIDEOIDLE"
            Value = 0
            AcDc = "AC"
        }


        #ProductKey Resources
        cWindowsLicense Server2022
        {
            Ensure = "Present"
            ProductKey = "NOT-FOR-YOU-SILLY"
            Activate = $true
        }


        #User Resources
        User localla
        {
            Ensure = "Present"
            Disabled = $false
            UserName = "localadmin"
            FullName = "localadmin"
            Password = $DMZlaPass
            PasswordChangeRequired = $false
            PasswordNeverExpires = $true
        }


        #File and Directory Resources
        File JumboDirectory
        {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = "C:\Jumbo"
        }

        File Temp
        {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = "C:\Temp"
        }


        #File downloading Resources
        xRemoteFile ArchiveDownload
        {
            URI = $resourceUri
            DestinationPath = "C:\Temp\2023Resources.zip"
            DependsOn = "[File]Temp"
        }

        xRemoteFile OfflineDomainJoin
        {
            URI = $odjUri
            DestinationPath = "C:\Jumbo\offlinedomainjoin.txt"
            DependsOn = "[File]JumboDirectory"
        }


        #Achive Extraction Resources
        Archive DMZResource
        {
            Ensure = "Present"
            Path = "C:\Temp\2023Resources.zip"
            Destination = "C:\Jumbo"
            DependsOn = "[xRemoteFile]ArchiveDownload"
        }


        #Offline Domain Join Resources
        OfflineDomainJoin EGOBRANECOM
        {
            RequestFile = "C:\Jumbo\offlinedomainjoin.txt"
            IsSingleInstance = "Yes"
            DependsOn = "[Archive]DMZResource"
        }        


        #Package Installation Resources - add build?
        Package Duo
        {
            Ensure = "Present"
            Name = "Duo Authentication for Windows Logon x64"
            Path = "C:\Jumbo\duo-win-login-4.2.0.exe"
            ProductId = "ADCB45A7-420D-4676-A2A2-0DA88BB3AD7B"
            Arguments = $DuoArguments
            DependsOn = @(
                "[Archive]DMZResource"
                "[OfflineDomainJoin]EGOBRANECOM"
            )
        }


        #Powershell Script Resources
        Script EnableRDP
        {
            TestScript = {
                if ((Get-NetFirewallRule -DisplayGroup "Remote Desktop").Enabled -ne "True") {
                    $false }
                        else {
                        $true }                    
            }

            SetScript = {
                Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
            }

            GetScript = {
                @{ Result = (Get-NetFirewallRule -DisplayGroup "Remote Desktop")}
            }
        }

        Script LocalAdminDMZRole
        {
            TestScript = {
                if ((Get-LocalGroupMember -Group "Administrators" | Out-String -Stream) -like '*BAMFORD*' -and (Get-LocalGroupMember -Group "Administrators" | Out-String -Stream) -like '*bamfordla*') {
                    $true }
                    else {
                        $false }
            }
            SetScript = {
                Add-LocalGroupMember -Group "Administrators" -Member 'Bamford', 'bamfordla'
            }
            GetScript = {
                @{ Result = (Get-LocalGroupMember -Group "Administrators" | Out-String -Stream)}
            }
        }
            
        Script DisableLocalAdminUser
        {
            TestScript = {
                if ((Get-LocalUser -Name "Administrator" | Out-String -Stream) -like "*True*") {
                    $false }
                    else {
                        $true }
            }
            SetScript = {
                Disable-LocalUser -Name "Administrator"
            }
            GetScript = {
                @{ Result = (Get-LocalUser -Name "Administrator")}
            }
        }
        
        Script CryptoWebServerStrict
        {
            TestScript = {
                if ((Get-TlsCipherSuite | Format-Table -HideTableHeaders).Count -eq 10) {
                    $true }
                    else {
                        $false }
            }
            SetScript = {
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
                Foreach ($insecureCipher in $insecureCiphers) {
                $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
                $key.SetValue('Enabled', 0, 'DWord')
                $key.close()
                }
    
                # Enable new secure ciphers.
                $secureCiphers = @(
                'AES 128/128',
                'AES 256/256'
                )
                Foreach ($secureCipher in $secureCiphers) {
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
                Foreach ($secureHash in $secureHashes) {
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
                Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
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
            GetScript = {
                @{ Result = (Get-TlsCipherSuite | Format-Table -HideTableHeaders | Out-String -Stream)}
            }

        }
    }
}