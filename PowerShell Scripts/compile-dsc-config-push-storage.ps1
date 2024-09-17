$storageAccountName = "egobranemisc"
$resourceGroup = "egobrane-Internal"
$tableName = "DSCParameters"
Connect-AzAccount -Environment AzureUSGovernment -UseDeviceAuthentication -Scope process
#Set-AzContext -Subscription $((Get-AzContext).Subscription.Id)
$storageAccountContext = (Get-AzStorageAccount -ResourceGroupName $resourceGroup -Name $storageAccountName).Context
$DSCTable = (Get-AzStorageTable -Name $tableName -Context $storageAccountContext).CloudTable
foreach ($job in $compileJobs)
{
    if (!(Get-AzTableRow -Table $DSCTable -PartitionKey $job))
    {
        [System.Collections.IDictionary]$compilationParams = Get-Variable -Name $job -ValueOnly
        foreach ($key in $compilationParams.keys)
        {
            $value = $compilationParams.$key.ToString()
            Add-AzTableRow -Table $DSCTable -PartitionKey $job -RowKey $key -property @{"value"="$value"}
        }
    }
    else 
    {
        Write-Host "This parameter value already exists. Skipping."
    }
}

Get-AzTableRow -Table $DSCTable -PartitionKey $job
$testHashTable = @{}
for ($i = 0; $i -lt (Get-AzTableRow -Table $DSCTable -PartitionKey $job).Count; $i++)
{
    write-host $i
}

Get-AzTableRow -Table $DSCTable -PartitionKey $parameterDefinition
$jobKeys = @((Get-AzTableRow -Table $DSCTable -PartitionKey $parameterDefinition).RowKey)
$jobValues = @((Get-AzTableRow -Table $DSCTable -PartitionKey $parameterDefinition).value)
$jobHashTable = @{}
for ($i = 0; $i -lt (Get-AzTableRow -Table $DSCTable -PartitionKey $parameterDefinition).Count; $i++)
{
    $jobHashTable.Add($jobKeys[$i], $jobValues[$i])
}
$parameterDefinition = $configurationName + "Params" + $jobHashTable.HostName
New-Variable -Name $parameterDefinition -Value $jobHashTable -Force
[System.Collections.ArrayList]$parameterDefinitions = @(($parameterDefinitions) + ($parameterDefinition))