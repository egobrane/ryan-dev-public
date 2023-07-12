Configuration ApplockerDeployment {

    #This is a new test - copying down policy from a repository
    param (
        [Parameter(Mandatory=$true)]
        [string]$NodeName,

        [Parameter(Mandatory=$true)]
        [string]$HostName
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Node $NodeName {

        #Applocker depends on AppIDsvc running
        Service AppIDsvc
        {
            Name = "AppIDSvc"
            State = "Running"
            BuiltinAccount = "LocalService"
            DependsOn = @(
                "[Script]ApplyLocalApplockerPol"
            )
        }

        #AppIDsvc is now a protected service and cannot set startup type through services.msc - only registry or GPO
        Registry AutoStartupAppID
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc"
            ValueName = "Start"
            ValueType = "Dword"
            ValueData = "2"
            Force = $true
        }

        #Download policy file
        xRemoteFile PolicyDownload
        {
            URI = "http://egobrane.com/dscresources/AppLocker/$HostName-pol.xml"
            DestinationPath = "C:\Temp\Applocker-pol.xml"
            DependsOn = "[Script]NewPolicyCheck"
        }

        #Check if remote policy has changed, and prep environment to download new version if so
        Script NewPolicycheck
        {
            TestScript = {
                $URL = "http://egobrane.com/dscresources/AppLocker/$using:HostName-pol.xml"
                $LocalPolicy = Get-Content -Path "C:\Temp\Applocker-pol.xml" -Raw
                $ReferencePolicy = Invoke-WebRequest -Uri $URL -UseBasicParsing | Select-Object -ExpandProperty Content

                if(
                    Compare-Object -ReferenceObject ([xml]$LocalPolicy).InnerXml `
                    -DifferenceObject ([xml]$ReferencePolicy).InnerXml
                ) {
                    $false }
                        else {
                        $true }
            }
            SetScript = {
                Remove-Item -Path "C:\Temp\Applocker-pol.xml"
            }
            GetScript = {
                @{
                    GetScript = $GetScript
                    SetScript = $SetScript
                    TestScript = $TestScript
                    Result = ([xml](Get-ApplockerPolicy -Effective -Xml)).InnerXml
                }
            }
        }
        #Apply policy located in Applocker-pol.xml
        Script ApplyLocalApplockerPol
        {
            TestScript = {
                if(
                    Compare-Object -ReferenceObject ([xml](Get-AppLockerPolicy -Effective -Xml)).InnerXML `
                    -DifferenceObject ([xml](Get-Content 'C:\Temp\Applocker-pol.xml')).InnerXml          
                ) {
                    $false }
                        else {
                        $true }
            }
            SetScript = {
                Set-AppLockerPolicy -XMLPolicy 'C:\Temp\Applocker-pol.xml'
            }
            GetScript = {
                @{
                    GetScript = $GetScript
                    SetScript = $SetScript
                    TestScript = $TestScript
                    Result = ([xml](Get-AppLockerPolicy -Effective -Xml)).InnerXML
                }
            }
            DependsOn = "[xRemoteFile]PolicyDownload"
        }
    }
}