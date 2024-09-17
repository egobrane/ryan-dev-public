


$resourceGroup = "egobrane-Internal";

$machines = (Get-AzConnectedMachine -ResourceGroupName $resourceGroup).Name

# $extension = "WindowsOsUpdateExtension"
# $extension = "WindowsPatchExtension"
# $extension = "DependencyAgentWindows"
$extension = "AzureMonitorWindowsAgent"
#machines with working OsUpdateExtension

$machinesWithOsUpdateExtensionInGoodState = @()
$machines | ForEach-Object {
    $machine = $_
	if (Get-AzConnectedMachineExtension -Name $extension -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue)
	{
		Write-Host "$machine status: " + (Get-AzConnectedMachineExtension -Name $extension -ResourceGroupName $resourceGroup -MachineName $machine).ProvisioningState
	}
    else
    {
        Write-Host "$machine does not have the Dependency Agent."
    }
}



#machines with working patch extension

$machines | ForEach-Object {
    $machine = $_
	if (Get-AzConnectedMachineExtension -Name "WindowsPatchExtension" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue)
	{
		Update-AzConnectedMachineExtension -ResourceGroupName $resourceGroup -MachineName $machine -Name "WindowsPatchExtension" -EnableAutomaticUpgrade:$false
	}
}


#disable auto updates
$machines | ForEach-Object {
    $machine = $_
	if ((Get-AzConnectedMachineExtension -Name "WindowsPatchExtension" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue).ProvisioningState -ne "Succeeded")
	{
		Update-AzConnectedMachineExtension -ResourceGroupName $resourceGroup -MachineName $machine -Name "WindowsPatchExtension" -EnableAutomaticUpgrade:$false
	}
}

$machinesWithoutOsUpdateExtension = @()
$machinesWithOsUpdateExtensionInBadState = @()
#get machines that don't have the OsUpdateExtension extension
$machines | ForEach-Object {
    $machine = $_
	if (!(Get-AzConnectedMachineExtension -Name "WindowsOsUpdateExtension" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue))
	{
		$machinesWithoutOsUpdateExtension += $machine
	}
	else
	{
		$machinesWithOsUpdateExtensionInBadState += ("$machine status: " + (Get-AzConnectedMachineExtension -Name "WindowsOsUpdateExtension" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue).ProvisioningState )
	}
}

$machinesWithoutPatchExtension = @()
$machinesWithPatchExtensionInBadState = @()
#get machines that don't have the OsUpdateExtension extension
$machines | ForEach-Object {
    $machine = $_
	if (!(Get-AzConnectedMachineExtension -Name "WindowsPatchExtension" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue))
	{
		$machinesWithoutPatchExtension += $machine
	}
	else
	{
		$machinesWithPatchExtensionInBadState += ("$machine status: " + (Get-AzConnectedMachineExtension -Name "WindowsPatchExtension" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue).ProvisioningState )
	}
}

$machinesWithoutMonitorExtension = @()
$machinesWithMonitorExtensionInBadState = @()
$machines | ForEach-Object {
    $machine = $_
	if (!(Get-AzConnectedMachineExtension -Name "AzureMonitorWindowsAgent" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue))
	{
		$machinesWithoutMonitorExtension += $machine
	}
	else
	{
		$machinesWithMonitorExtensionInBadState += ("$machine status: " + (Get-AzConnectedMachineExtension -Name "AzureMonitorWindowsAgent" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue).ProvisioningState )
	}
}

$machinesWithoutDependencyExtension = @()
$machinesWithDependencyExtensionInBadState = @()
$machines | ForEach-Object {
    $machine = $_
	if (!(Get-AzConnectedMachineExtension -Name "DependencyAgentWindows" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue))
	{
		$machinesWithoutDependencyExtension += $machine
	}
	else
	{
		$machinesWithDependencyExtensionInBadState += ("$machine status: " + (Get-AzConnectedMachineExtension -Name "DependencyAgentWindows" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue).ProvisioningState )
	}
}


$machinesWithMonitoringAgent = @()
$machines | ForEach-Object {
    $machine = $_
	if (Get-AzConnectedMachineExtension -Name "MicrosoftMonitoringAgent" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue)
	{
		$machinesWithMonitoringAgent += ("$machine status: " + (Get-AzConnectedMachineExtension -Name "MicrosoftMonitoringAgent" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue).ProvisioningState )
	}
}