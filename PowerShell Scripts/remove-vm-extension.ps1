$resourceGroup = "egobrane-Internal";
# $resourceGroup = "egobrane-Cloud-TX-TestPD";
# $location = "USGov Texas";\
# DMZRODC1, dmz-sql
$machines = @(
)


#$machines = (Get-AzConnectedMachine -ResourceGroupName $resourceGroup | Where-Object {$_.Status -eq "Connected"}).Name

foreach ($machine in $machines)
{
    if ((Get-AzConnectedMachineExtension -Name "MicrosoftMonitoringAgent" -ResourceGroupName $resourceGroup -MachineName $machine -ErrorAction SilentlyContinue).ProvisioningState )
    {
        Remove-AzConnectedMachineExtension -Name "MicrosoftMonitoringAgent" -ResourceGroupName $resourceGroup -MachineName $machine
        Write-Host "MMA Agent uninstalled from $machine"
    }
    else {
        Write-Host "$machine does not have the MicrosoftMonitoringAgent extension."
    }
}