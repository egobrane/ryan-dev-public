[DscLocalConfigurationManager()]
#This script is for onboarding to Azure Automation. Replace RegistrationUrl and RegistrationKey parameters with ACISS values
Configuration DscMetaConfigs
{
     param
     (
         [Parameter(Mandatory=$True)]
         [String]$RegistrationUrl,

         [Parameter(Mandatory=$True)]
         [String]$RegistrationKey,

         [Parameter(Mandatory=$True)]
         [String[]]$ComputerName,

         [Int]$RefreshFrequencyMins = 30,

         [Int]$ConfigurationModeFrequencyMins = 15,

         [String]$ConfigurationMode = 'ApplyAndAutoCorrect',

         [String]$NodeConfigurationName,

         [Boolean]$RebootNodeIfNeeded= $False,

         [String]$ActionAfterReboot = 'ContinueConfiguration',

         [Boolean]$AllowModuleOverwrite = $False,

         [Boolean]$ReportOnly
     )

     if(!$NodeConfigurationName -or $NodeConfigurationName -eq '')
     {
         $ConfigurationNames = $null
     }
     else
     {
         $ConfigurationNames = @($NodeConfigurationName)
     }

     if($ReportOnly)
     {
         $RefreshMode = 'PUSH'
     }
     else
     {
         $RefreshMode = 'PULL'
     }

     Node $ComputerName
     {
         Settings
         {
             RefreshFrequencyMins           = $RefreshFrequencyMins
             RefreshMode                    = $RefreshMode
             ConfigurationMode              = $ConfigurationMode
             AllowModuleOverwrite           = $AllowModuleOverwrite
             RebootNodeIfNeeded             = $RebootNodeIfNeeded
             ActionAfterReboot              = $ActionAfterReboot
             ConfigurationModeFrequencyMins = $ConfigurationModeFrequencyMins
         }

         if(!$ReportOnly)
         {
         ConfigurationRepositoryWeb AzureAutomationStateConfiguration
             {
                 ServerUrl          = $RegistrationUrl
                 RegistrationKey    = $RegistrationKey
                 ConfigurationNames = $ConfigurationNames
             }

             ResourceRepositoryWeb AzureAutomationStateConfiguration
             {
                 ServerUrl       = $RegistrationUrl
                 RegistrationKey = $RegistrationKey
             }
         }

         ReportServerWeb AzureAutomationStateConfiguration
         {
             ServerUrl       = $RegistrationUrl
             RegistrationKey = $RegistrationKey
         }
     }
}

$Params = @{
     RegistrationUrl = 'http://egobrane.com/privateurl';
     RegistrationKey = 'ipjf40923jf0-893q4jw089fj3wsopajfvidfjgp[jaeqgr09-rgjo';
     ComputerName = @('localhost');
     RefreshFrequencyMins = 30;
     ConfigurationModeFrequencyMins = 15;
     RebootNodeIfNeeded = $True;
     AllowModuleOverwrite = $True;
     ConfigurationMode = 'ApplyAndAutoCorrect';
     ActionAfterReboot = 'ContinueConfiguration';
     ReportOnly = $False;  # Set to $True to have machines only report to AA DSC but not pull from it
}


DscMetaConfigs @Params