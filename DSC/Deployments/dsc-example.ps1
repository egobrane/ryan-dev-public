#Define name for Configuration - must match intended name in Azure Automation
Configuration TestConfigName {

	param (
		[Parameter(Mandatory = $true)]
		[string]$hostName
	)

	#Import Desired DSC Modules - Must be present in Azure Automation
	Import-DscResource -ModuleName PSDesiredStateConfiguration

	$variableExample = "C:\Temp"

	Node $hostName {

		#Ensure Web-Server feature is present
		WindowsFeature WindowsFeatureName
		{
			Name   = "Web-Server"
			Ensure = "Present"
		}

		#This is a script resource and can do anything powershell can do.
		Script ScriptResourceName
		{
			#TestScript must return boolean. If true, node is compliant. If false, runs SetScript
			TestScript = {
				#When calling variables outside of script resource, must use the using scope
				Test-Path $using:variableExample
			}
			SetScript  = {
				New-Item -ItemType Directory -Path $using:variableExample
			}
			#GetScript is for diagnostics of a node and called upon with Get-DscLocalConfigurationManager
			GetScript  = {
				@{ Result = (Test-Path $using:variableExample) }
			}
		}
	}
}