Configuration ApplockerTest {

    #This is a test - just manually placing contents of a file. 
    param (
        [string[]]$NodeName = 'localhost'
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
                "[File]XMLPol"
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

        #Apply policy located in Applocker-pol.xml
        Script ApplyLocalApplockerPol
        {
            TestScript = {
                if(
                    Compare-Object -ReferenceObject ([xml](Get-AppLockerPolicy -Effective -Xml)).InnerXML `
                    -DifferenceObject ([xml](Get-Content 'C:\Temp\Applocker-pol.xml')).InnerXml          
                ) {
                    return $false
                } else {
                    return $true
                }
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
            DependsOn = "[File]XMLPol"
        }

        File XMLPol
        {
            DestinationPath = "C:\Temp\Applocker-pol.xml"
            Ensure = "Present"
            Force = $true
            Contents = @'
            <AppLockerPolicy Version="1">
            <RuleCollection Type="Appx" EnforcementMode="Enabled">
              <FilePublisherRule Id="0f66e102-0474-480e-9df2-9364614a2f11" Name="Signed by Microsoft Corporation" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
                <Conditions>
                  <FilePublisherCondition PublisherName="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" ProductName="*" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*" />
                  </FilePublisherCondition>
                </Conditions>
              </FilePublisherRule>
            </RuleCollection>
            <RuleCollection Type="Dll" EnforcementMode="NotConfigured" />
            <RuleCollection Type="Exe" EnforcementMode="Enabled">
              <FilePublisherRule Id="1d22bf95-b780-49dd-b1cd-875405764112" Name="Signed by O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
                <Conditions>
                  <FilePublisherCondition PublisherName="O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="*" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*" />
                  </FilePublisherCondition>
                </Conditions>
              </FilePublisherRule>
              <FilePublisherRule Id="7e6453ab-5a03-4718-8b1b-384206d40010" Name="Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
                <Conditions>
                  <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*" />
                  </FilePublisherCondition>
                </Conditions>
              </FilePublisherRule>
              <FilePathRule Id="894b62f4-c9ae-4b69-930b-fbe0d347dfb9" Name="%PROGRAMFILES%\MICROSOFT\*" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
                <Conditions>
                  <FilePathCondition Path="%PROGRAMFILES%\MICROSOFT\EDGE\APPLICATION\" />
                </Conditions>
              </FilePathRule>
              <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule) All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
                <Conditions>
                  <FilePathCondition Path="%WINDIR%\*" />
                </Conditions>
              </FilePathRule>
            </RuleCollection>
            <RuleCollection Type="Msi" EnforcementMode="Enabled" />
            <RuleCollection Type="Script" EnforcementMode="NotConfigured" />
          </AppLockerPolicy>
'@
        }

    }
}