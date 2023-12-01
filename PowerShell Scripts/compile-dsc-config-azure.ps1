#Compile Configurations
$configurationName = "egobranepc"

$hostNames = @(
	'dmz-egobrane'
)   

$Parameters = @{
    'hostName' = ''
    'YearRange' = '2023-2024'
}

foreach ($hostName in $hostNames) {
    $Parameters.hostName = $hostName
    Start-AzAutomationDscCompilationJob -ResourceGroupName 'egobrane-Internal' -AutomationAccountName 'egobrane-Internal-AA' `
	-ConfigurationName $configurationName -Parameters $Parameters
}

#Get list of IDs to Names
$searchTerm = "egobraneWEB"
$idArray = (Get-AzAutomationDscNode -ResourceGroupName "egobrane-Internal" -AutomationAccountName "egobrane-Internal-AA" `
| Select-Object -Property Name,Id | Where-Object {$_.Name -like "*$searchTerm*"}).Id
$nameArray = (Get-AzAutomationDscNode -ResourceGroupName "egobrane-Internal" -AutomationAccountName "egobrane-Internal-AA" `
| Select-Object -Property Name,Id | Where-Object {$_.Name -like "*$searchTerm*"}).Name


#Assign Nodes

$deviceName = "egodesktop2";
$nodeConfigurationName = "Workstation.localhost";
$deviceId = (Get-AzAutomationDscNode -ResourceGroupName "egobrane-Internal" -AutomationAccountName "egobrane-Internal-AA" -name $deviceName).Id;
Set-AzAutomationDscNode -ResourceGroupName "egobrane-Internal" -AutomationAccountName "egobrane-Internal-AA" -id $deviceId -NodeConfigurationName $nodeConfigurationName -force;