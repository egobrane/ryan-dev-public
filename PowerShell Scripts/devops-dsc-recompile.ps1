$targetParams = @{
	ResourceGroupName = "egobraneinternal"
	AutomationAccountName = "egobrane-Internal-AA"
}

# Test get changed configuration?
$updatedConfigurations = @((Get-ChildItem C:\Dev\ryan-dev\DSC\Deployments | Where-Object {$_.LastWriteTime -gt $(Get-Date -Format "MM/dd/yyyy")}).FullName)
foreach ($configuration in $updatedConfigurations)
{
	$configurationName = ((Get-Content $configuration -First 1).TrimStart('Configuration ').TrimEnd(' {'))
	# initiate variable used to determine if all compilations were successful
	$compileJobHistory = @("Suspended", "Completed")

	do
	{
		#PARAMETERS MUST BE retrieved before upload, because upload and replace removes compilation history!!, default values other than those with specific hostnames?
		#There's a bug where older compilation jobs can't load the history... this is also present in the azure portal. need to resolve this
		if ($firstRun -ne $false)
		{
			$compilationIds = @((Get-AzAutomationDscCompilationJob @targetParams -ConfigurationName $configurationName | Where-Object {$_.Status -eq "Completed"}).Id)
		}
		elseif ($firstRun -eq $false)
		{
			$compilationIds = @((Get-AzAutomationDscCompilationJob @targetParams -ConfigurationName $configurationName| Where-Object {$_.Status -eq "Suspended"}).Id)
			$parameterDefinitions = @()
		}
		Write-Host "Gathering input parameters..."

		foreach ($Id in $compilationIds)
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
				[System.Collections.ArrayList]$parameterDefinitions = @(($parameterDefinitions) + ($parameterDefinition))
		}

		#upload configuration, according to Microsoft on Azure Powershell's github, file name must match configuration name for upload. There is no parameter to override this.
		#https://github.com/Azure/azure-powershell/issues/12384#issuecomment-683463648
		if ($firstRun -ne $false)
		{
			Import-AzAutomationDscConfiguration @targetParams -SourcePath $configuration -Published -Force
		}

		$compileTime = Get-Date -Format "MM/dd/yyyy hh:mm tt"
		foreach ($definition in $parameterDefinitions)
		{
			[System.Collections.IDictionary]$compilationParams = Get-Variable -Name $definition -ValueOnly
			Start-AzAutomationDscCompilationJob @targetParams -ConfigurationName $configurationName -Parameters $compilationParams
		}

		do
		{
			#sometimes compilation jobs inexplicably get queued for awhile before processing, yes it sometimes takes too long
			Write-Host "Waiting for compilation to complete..."
			Start-Sleep -Minutes 7
			$compileJobHistory = @((Get-AzAutomationDscCompilationJob @targetParams | Where-Object ({$_.ConfigurationName -eq $configurationName -and $_.StartTime -gt $compileTime})).Status)
		} until ($compileJobHistory -notcontains "Running")

		if ($compileJobHistory -contains "Suspended")
		{
			Write-Host "Failed jobs detected. Trying again..."
			$firstRun = $false
		}
	} while ($compileJobHistory -contains "Suspended")
}