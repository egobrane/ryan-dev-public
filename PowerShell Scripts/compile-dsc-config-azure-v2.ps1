$targetParams = @{
	ResourceGroupName = "egobrane-Internal"
	AutomationAccountName = "egobrane-Internal-AA"
}
$storageAccountName = "egobranemisc"
$resourceGroup = "egobrane-Internal"
$tableName = "DSCParameters"
#Connect-AzAccount -Environment AzureUSGovernment -UseDeviceAuthentication -Scope Process
$storageAccountContext = (Get-AzStorageAccount -ResourceGroupName $resourceGroup -Name $storageAccountName).Context
$DSCTable = (Get-AzStorageTable -Name $tableName -Context $storageAccountContext).CloudTable
$updatedConfigurations = @(
)
$updatedConfigurations = @((Get-ChildItem /Users/ryanbamford/Dev/ryan-dev/DSC/Deployments | Where-Object {$_.LastWriteTime -gt $(Get-Date -Format "MM/dd/yyyy")}).FullName)
foreach ($configuration in $updatedConfigurations)
{
	$configurationName = (Split-Path -Path $configuration -Leaf).TrimEnd('.ps1')
	# initiate variable used to determine if all compilations were successful
	$compileJobHistory = @("Suspended", "Completed")
	$parameterDefinitions = @()
	$firstRun = $true

	do
	{
		if ($firstRun -eq $true)
		{
			#$compilationIds = @((Get-AzAutomationDscCompilationJob @targetParams -ConfigurationName $configurationName | Where-Object {$_.Status -eq "Completed"}).Id)
			$activeCompilations = @((Get-AzAutomationDscNodeConfiguration @targetParams | Where-Object {$_.ConfigurationName -eq $configurationName}).Name)
			$storedCompilations = @((Get-AzTableRow -Table $DSCTable | Where-Object {$_.PartitionKey -like "$configurationName*"}).PartitionKey | Sort-Object | Get-Unique )
			foreach ($activeCompilation in $activeCompilations)
			{
				if ("$configurationName" + "Params" + $activeCompilation.ToLower().TrimStart("$configurationName").Trim(".") -in $storedCompilations)
				{
					Write-Host "Found $activeCompilation Parameters in Azure Storage."
				}
				else
				{
					Write-Host "Did not find $activeCompilation Parameters in Azure Storage. Adding them."
					$compilationIds = @((Get-AzAutomationDscCompilationJob @targetParams -ConfigurationName $configurationName | Where-Object {$_.Status -eq "Completed"}).Id)
					foreach ($Id in $compilationIds)
					{
						if (((Get-AzAutomationDscCompilationJob @targetParams -Id $Id).JobParameters.Values.Trim("""") | Out-String -Stream ) `
						-like $activeCompilation.ToLower().TrimStart("$configurationName").Trim("."))
						{
							$jobKeys = @((Get-AzAutomationDscCompilationJob @targetParams -Id $Id).JobParameters.Keys)
							$jobValues = @((Get-AzAutomationDscCompilationJob @targetParams -Id $Id).JobParameters.Values.Trim(""""))
							$jobHash = @{}
							for ($i = 0; $i -lt $jobValues.Count; $i++)
							{
								$jobHash.Add($jobKeys[$i], $jobValues[$i])
							}
							$parameterDefinition = $configurationName + "Params" + $jobHash.HostName
							New-Variable -Name $parameterDefinition -Value $jobHash -Force
							[System.Collections.IDictionary]$compilationParams = Get-Variable -Name $parameterDefinition -ValueOnly
							foreach ($key in $compilationParams.keys)
							{
								$value = $compilationParams.$key.ToString()
								Add-AzTableRow -Table $DSCTable -PartitionKey $parameterDefinition -RowKey $key -property @{"value"="$value"}
							}
						}
					}
					$storedCompilations = @((Get-AzTableRow -Table $DSCTable | Where-Object {$_.PartitionKey -like "$configurationName*"}).PartitionKey | Sort-Object | Get-Unique )
				}
			}
			foreach ($storedCompilation in $storedCompilations)
			{
				Write-Host "Building $storedCompilation parameter hash table."
				$jobKeys = @((Get-AzTableRow -Table $DSCTable -PartitionKey $storedCompilation).RowKey)
				$jobValues = @((Get-AzTableRow -Table $DSCTable -PartitionKey $storedCompilation).value)
				$jobHash = @{}
				for ($i = 0; $i -lt (Get-AzTableRow -Table $DSCTable -PartitionKey $storedCompilation).Count; $i++)
				{
					$jobHash.Add($jobKeys[$i], $jobValues[$i])
				}
				$parameterDefinition = $configurationName + "Params" + $jobHash.HostName
				New-Variable -Name $parameterDefinition -Value $jobHash -Force
				[System.Collections.ArrayList]$parameterDefinitions = @(($parameterDefinitions) + ($parameterDefinition))
			}
		}
		elseif ($firstRun -eq $false)
		{
			$compilationIds = @((Get-AzAutomationDscCompilationJob @targetParams | Where-Object ({$_.ConfigurationName -eq $configurationName -and $_.StartTime -gt $compileTime -and $_.Status -eq "Suspended"})).Id)
			$parameterDefinitions = @()
			foreach ($Id in $compilationIds)
			{
					#maybe just do lookup once?
					$jobKeys = @((Get-AzAutomationDscCompilationJob @targetParams -Id $Id).JobParameters.Keys)
					$jobValues = @((Get-AzAutomationDscCompilationJob @targetParams -Id $Id).JobParameters.Values.Trim(""""))
					$jobHash = @{}
					for ($i = 0; $i -lt $jobValues.Count; $i++)
					{
						$jobHash.Add($jobKeys[$i], $jobValues[$i])
					}
					$parameterDefinition = $configurationName + "Params" + $jobHash.HostName
					New-Variable -Name $parameterDefinition -Value $jobHash -Force
					[System.Collections.ArrayList]$parameterDefinitions = @(($parameterDefinitions) + ($parameterDefinition))
			}
		}
		Write-Host "Gathering input parameters..."
		$compileJobs = $parameterDefinitions | Get-Unique

		if ($firstRun -ne $false)
		{
			Import-AzAutomationDscConfiguration @targetParams -SourcePath $configuration -Published -Force
		}

		$compileTime = Get-Date -Format "MM/dd/yyyy hh:mm tt"
		foreach ($job in $compileJobs)
		{
			[System.Collections.IDictionary]$compilationParams = Get-Variable -Name $job -ValueOnly
			Start-AzAutomationDscCompilationJob @targetParams -ConfigurationName $configurationName -Parameters $compilationParams
		}

		do
		{
			#sometimes compilation jobs inexplicably get queued for awhile before processing, yes it sometimes takes too long
			Write-Host "Waiting for compilation to complete..."
			Start-Sleep -Seconds 420
			$compileJobHistory = @((Get-AzAutomationDscCompilationJob @targetParams | Where-Object ({$_.ConfigurationName -eq $configurationName -and $_.StartTime -gt $compileTime})).Status)
		} until ($compileJobHistory -notcontains "Running")

		if ($compileJobHistory -contains "Suspended")
		{
			Write-Host "Failed jobs detected. Trying again..."
			$firstRun = $false
		}
	} while ($compileJobHistory -contains "Suspended")

	Write-Host "$configurationName redeployed to all associated nodes."
}
