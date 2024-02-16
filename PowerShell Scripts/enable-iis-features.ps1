# This script enables relevant IIS features, there is some fuckery involved with the way Windows processes these installs
# hence, the weird scripting

Get-WindowsOptionalFeature -Online |
Where-Object { ($_.FeatureName -like "IIS*") -and ($_.State -eq "Enabled") } |
Disable-WindowsOptionalFeature -Online -NoRestart

$intendedIISFeatures = @(
	'IIS-WebServerRole'
	'IIS-WebServerManagementTools'
	'IIS-ManagementConsole'
)
foreach ($IISFeature in $intendedIISFeatures)
{
	Enable-WindowsOptionalFeature -Online -FeatureName $IISFeature -NoRestart
}

$unintendedIISFeatures = @(
	'IIS-WebServer'
	'IIS-CommonHttpFeatures'
	'IIS-HttpErrors'
	'IIS-ApplicationDevelopment'
	'IIS-Security'
	'IIS-RequestFiltering'
	'IIS-HealthAndDiagnostics'
	'IIS-HttpLogging'
	'IIS-Performance'
	'IIS-StaticContent'
	'IIS-DefaultDocument'
	'IIS-DirectoryBrowsing'
	'IIS-HttpCompressionStatic'
)
foreach ($IISFeature in $unintendedIISFeatures)
{
	Disable-WindowsOptionalFeature -Online -FeatureName $IISFeature -NoRestart -ErrorAction SilentlyContinue
}
Restart-Computer -Force


# This portion tests to make sure that relevant features are enabled

$intendedIISFeatures = @(
	'IIS-WebServerRole'
	'IIS-WebServerManagementTools'
	'IIS-ManagementConsole'
)
$currentIISFeatures = (Get-WindowsOptionalFeature -Online |
	Where-Object { ($_.FeatureName -like "IIS*") -and ($_.State -eq "Enabled") }).FeatureName
$featureMatch = @(Compare-Object -ReferenceObject @($intendedIISFeatures | Select-Object) `
		-DifferenceObject @($currentIISFeatures | Select-Object)).Length -eq 0
$featureMatch