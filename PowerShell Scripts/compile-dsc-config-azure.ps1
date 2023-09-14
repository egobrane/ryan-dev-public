#Compile Configurations
$configurationName = "DmzWebServerv3"

$hostNames = @(
	'localhost',
	'other-localhost'
)   

$Parameters = @{
    'hostName' = ''
    'YearRange' = '2022-2023'
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


#Assign Nodes, not working yet

foreach ($searchResult in $searchArray) {
	Set-AzAutomationDscNode -NodeConfigurationName "$configurationName.$"
}