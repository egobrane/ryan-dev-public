# This script enables all relevant remote server administration tools 

$capabilityArray = @(
	'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
	'Rsat.DHCP.Tools~~~~0.0.1.0'
	'Rsat.Dns.Tools~~~~0.0.1.0'
	'Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0'
	'Rsat.FileServices.Tools~~~~0.0.1.0'
	'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
	'Rsat.ServerManager.Tools~~~~0.0.1.0'
	'Rsat.WSUS.Tools~~~~0.0.1.0'
)
foreach ($capability in $capabilityArray)
{
	Add-WindowsCapability -Online -Name $capability
}

$intendedHyperVFeatures = @(
	'Microsoft-Hyper-V-All'
	'Microsoft-Hyper-V-Tools-All'
	'Microsoft-Hyper-V-Management-PowerShell'
	'Microsoft-Hyper-V-Management-Clients'
)
foreach ($hyperVFeature in $intendedHyperVFeatures)
{
	Enable-WindowsOptionalFeature -Online -FeatureName $hyperVFeature
}

# This script checks to make sure that all relevant remote server administration tools are installed

$intendedCapabilities = @(
	'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
	'Rsat.DHCP.Tools~~~~0.0.1.0'
	'Rsat.Dns.Tools~~~~0.0.1.0'
	'Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0'
	'Rsat.FileServices.Tools~~~~0.0.1.0'
	'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
	'Rsat.ServerManager.Tools~~~~0.0.1.0'
	'Rsat.WSUS.Tools~~~~0.0.1.0'
)
$currentCapabilities = (Get-WindowsCapability -Name Rsat* -Online |
	Where-Object { $_.State -eq "Installed" }).Name
$capabilityMatch = @(Compare-Object -ReferenceObject @($intendedCapabilities | Select-Object) `
		-DifferenceObject @($currentCapabilities | Select-Object)).Length -eq 0
$capabilityMatch

$intendedHyperVFeatures = @(
	'Microsoft-Hyper-V-All'
	'Microsoft-Hyper-V-Tools-All'
	'Microsoft-Hyper-V-Management-PowerShell'
	'Microsoft-Hyper-V-Management-Clients'
)
$currentHyperVFeatures = (Get-WindowsOptionalFeature -Online |
	Where-Object { ($_.FeatureName -like "Microsoft-Hyper-V*") -and ($_.State -eq "Enabled") }).FeatureName
$featureMatch = @(Compare-Object -ReferenceObject @($intendedHyperVFeatures | Select-Object) `
		-DifferenceObject @($currentHyperVFeatures | Select-Object)).Length -eq 0
$featureMatch