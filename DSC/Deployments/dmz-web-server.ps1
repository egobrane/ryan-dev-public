Configuration DmzWebServerv2 {

# THIS SCRIPT WILL NOT WORK. THIS IS A PUBLIC COMMIT OF A PRIVATE RESOURCE WITH CERTAIN VARIABLES OBSCURED.
# It is for my documentation only.

    #Update ODJ URI with Blob SAS URI for this instance
    param (
        [Parameter(Mandatory=$true)]
        [string]$HostName,

        [Parameter(Mandatory=$true)]
        [string]$odjUri
    )
    
    #Import Modules for all necessary DSC resources - must be in Azure Automation
    Import-DscResource -ModuleName ComputerManagementDSC
    Import-DscResource -ModuleName WebAdministrationDsc
    Import-DscResource -ModuleName DSCR_MSLicense
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName DSCR_PowerPlan
    Import-DscResource -ModuleName CertificateDsc
    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    #pull variables from automation here
    $symlinkCred = Get-AutomationPSCredential -Name "SymlinkAutomationCred"
    $23certPass = Get-AutomationPSCredential -Name "SSLCertCred"
    $DMZLocalAdminTest = Get-AutomationPSCredential -Name "$HostName-LocalAdminPass"
    $resourceUri = "http://egobrane.com"


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
            ProductKey = "private-information-silly-boys"
            Activate = $true
        }


        #User Resources
        User acissla
        {
            Ensure = "Present"
            Disabled = $false
            UserName = "localadmintest"
            FullName = "local admin test"
            Password = $DMZLocalAdminTest
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

        File MapData
        {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = "C:\Jumbo\MapData"
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
            Destination = "C:\Jumbo\"
            DependsOn = "[xRemoteFile]ArchiveDownload"
        }


        #Offline Domain Join Resources
        OfflineDomainJoin EGOBRANENET
        {
            RequestFile = "C:\Jumbo\offlinedomainjoin.txt"
            IsSingleInstance = "Yes"
            DependsOn = "[Archive]DMZResource"
        }        


        #Server Roles and Features Resources
        WindowsFeatureSet DMZNETFramework
        {
            Name = @(
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

        WindowsFeatureSet DMZWebServer
        {
            Name = @(
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

        WindowsFeatureSet DMZStorageServices
        {
            Name = @(
                "FileAndStorage-Services"
                "Storage-Services"
                )
            Ensure = "Present"
        }


        #IIS Logging Resources
        IisLogging FullLogs
        {
            LogPath = "%SystemDrive%\inetpub\logs\LogFiles"
            Logflags = @(
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
            LogFormat = "W3C" 
            LogPeriod = "Daily"
            LogTargetW3C = "File"
            LogCustomFields = DSC_LogCustomField
            {
                LogFieldName = "X-Forwarded-For"
                SourceName = "X-Forwarded-For"
                SourceType = "RequestHeader"
                Ensure = "Present"
            }
            DependsOn = "[WindowsFeatureSet]DMZWebServer"
        }


        #IIS SSL Bindings Resource
        WebSite SSLBindings
        {
            Ensure = "Present"
            Name = "Default Web Site"
            DependsOn = @(
                "[PfxImport]StarACISS"
                "[WindowsFeatureSet]DMZWebServer"
            )
            BindingInfo = @(
                DSC_WebBindingInformation
                {
                    Protocol = "HTTPS"
                    Port = "443"
                    CertificateStoreName = "MY"
                    CertificateThumbprint = "ThumbprintGoesHere"
                    IPAddress = "*"
                }
                DSC_WebBindingInformation
                {
                    Protocol = "HTTP"
                    Port = "80"
                    IpAddress = "*"
                }
            )
        }

        #SSL Certificate Resources
        PfxImport StarACISS
        {
            Thumbprint = "ThumbprintGoesHere"
            Path = "C:\ACISS\STAR_Egobrane_com_2022-2023.pfx"
            Location = "LocalMachine"
            Store = "My"
            Credential = $23certPass
            Ensure = "Present"
            FriendlyName = "Egobrane Cert"
            DependsOn = "[Archive]DMZResource"
        }


        #Package Installation Resources - add build?
        Package Duo
        {
            Ensure = "Present"
            Name = "Duo Authentication for Windows Logon x64"
            Path = "C:\Jumbo\duo-win-login-4.2.0.exe"
            ProductId = "ADCB45A7-420D-4676-A2A2-0DA88BB3AD7B"
            Arguments = $DuoInstallArguments
            DependsOn = @(
                "[Archive]DMZResource"
                "[OfflineDomainJoin]ACISSCOM"
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

        Script DisableNetworkDiscovery
        {
            TestScript = {
                if ((Get-NetFirewallRule -DisplayGroup "Network Discovery").Enabled -ne "False") {
                    $false }
                        else {
                        $true }                    
            }
            
            SetScript = {
                Disable-NetFirewallRule -DisplayGroup "Network Discovery"
            }

            GetScript = {
                @{ Result = (Get-NetFirewallRule -DisplayGroup "Network Discovery")}
            }
        }

        Script LocalAdminDMZRole
        {
            TestScript = {
                if ((Get-LocalGroupMember -Group "Administrators" | Out-String -Stream) -like '*EGOBRANENET\Admins*' -and (Get-LocalGroupMember -Group "Administrators" | Out-String -Stream) -like '*dmzadmin*') {
                    $true }
                    else {
                        $false }
            }
            SetScript = {
                Add-LocalGroupMember -Group "Administrators" -Member 'EGOBRANENET\Admins', 'egobranela'
            }
            GetScript = {
                @{ Result = (Get-LocalGroupMember -Group "Administrators" | Out-String -Stream)}
            }
        }
            
        Script SymbolicGeocode
        {
            TestScript = {
                if (Test-Path -Path "C:\Jumbo\GeocodeData") {
                    $true }
                    else {
                        $false }                    
            }            
            SetScript = {
                New-Item -ItemType SymbolicLink -Path "C:\Jumbo\GeocodeData\" -Target "\\egosql\GeocodeData\"
            }
            GetScript = {
                @{ Result = (Get-ChildItem "C:\Jumbo\")}
            }
            PsDscRunAsCredential = $symlinkCred
            DependsOn = @(
                "[Script]MapData"
            )
        }

        Script MapData
        {
            TestScript = {
                if (Test-Path -Path "C:\Jumbo\MapData\Vector20220518\") {
                    $true }
                    else {
                        $false }
            }
            SetScript = {
                New-Item -ItemType SymbolicLink -Path "C:\Jumbo\MapData\Vector20220518\" -Target "\\egosql\MapData\Vector20220518\"
            }
            GetScript = {
                @{ Result = (Get-ChildItem "C:\Jumbo\")}
            }
            PsDscRunAsCredential = $symlinkCred
            DependsOn = @(
                "[OfflineDomainJoin]EGOBRANENET"
                "[File]MapData"
            )
        }

        Script RemoveXPoweredHeader
        {
            TestScript = {
                if ((Get-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']" | Out-String -Stream ) -like "*X-Powered-By*") {
                    $false }
                    else {
                        $true }                    
            }
            SetScript = {
                Clear-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']"
            }
            GetScript = {
                @{ Result = (Get-WebConfiguration "system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']" | Out-String -Stream )}
            }
            DependsOn = "[WindowsFeatureSet]DMZWebServer"
        }

        Script AddTransportHeader
        {
            TestScript = {
                if ((Get-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders/add" -PSPath "IIS:\Sites\Default Web Site" -Name value | Out-String -Stream) -like "*Strict-Transport-Security*") {
                    $true }
                    else {
                        $false }
            }
            SetScript = {
                Add-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" -PSPath "IIS:\Sites\Default Web Site" -Name . -Value @{name="Strict-Transport-Security"; value="max-age=31536000; includeSubDomains"}
            }
            GetScript = {
                @{ Result = (Get-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders/add" -PSPath "IIS:\Sites\Default Web Site" -Name value | Out-String -Stream )}
            }
            DependsOn = "[WindowsFeatureSet]DMZWebServer"
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