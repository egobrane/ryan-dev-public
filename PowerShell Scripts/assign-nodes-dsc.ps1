#Assign Nodes
$nodes = @(
    "Remote1"
    "Remote2"
    "Remote3"
    "Remote4"
    "Remote5"
    "Remote6"

)

foreach ($node in $nodes)
{
    $nodeConfigurationName = "remote_vm.localhost";
    $deviceId = (Get-AzAutomationDscNode -ResourceGroupName "egobrane-Internal" -AutomationAccountName "egobrane-Internal-AA" -name $node).Id;
    Set-AzAutomationDscNode -ResourceGroupName "egobrane-Internal" -AutomationAccountName "egobrane-Internal-AA" -id $deviceId -NodeConfigurationName $nodeConfigurationName -force;
}



