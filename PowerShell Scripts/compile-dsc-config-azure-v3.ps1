$targetParams = @{
	ResourceGroupName = "egobrane-Internal"
	AutomationAccountName = "egobrane-Internal-AA"
}
$compileJobHistory = @("Suspended", "Completed")
# Connect-AzAccount -Environment AzureUSGovernment -UseDeviceAuthentication -Scope Process
$updatedConfigurations = @(
	"/Users/ryanbamford/Dev/ryan-dev/DSC/Deployments/agency_web_db.ps1"
	"/Users/ryanbamford/Dev/ryan-dev/DSC/Deployments/agency_web.ps1"
)
# $updatedConfigurations = @((Get-ChildItem ../DSC/Deployments | Where-Object {$_.LastWriteTime -gt $(Get-Date -Format "MM/dd/yyyy")}).FullName)
$jobTime = Get-Date -Format "MM/dd/yyyy hh:mm tt"
$firstRun = $true
do
{
	if ($firstRun -eq $true)
	{
		foreach ($configuration in $updatedConfigurations)
		{
			$configurationName = (Split-Path -Path $configuration -Leaf).TrimEnd('.ps1')
			Import-AzAutomationDscConfiguration @targetParams -SourcePath $configuration -Published -Force
			Start-AzAutomationDscCompilationJob @targetParams -ConfigurationName $configurationName
		}
	}
	if ($firstRun -eq $false)
	{
		$suspendedJobs = @((Get-AzAutomationDscCompilationJob @targetParams | Where-Object {$_.StartTime -gt $jobTime -and $_.Status -eq "Suspended"}))
		foreach ($job in $suspendedJobs)
		{
			#$configurationName = (Get-AzAutomationDscCompilationJob @targetParams | Where-Object {$_.StartTime -gt $jobTime -and $_.ConfigurationName -eq $job.ConfigurationName}).ConfigurationName
			Start-AzAutomationDscCompilationJob @targetParams -ConfigurationName ($job.ConfigurationName | Out-String -Stream)
		}
	}
	Write-Host "Waiting 2 minutes for compilations to begin processing..."
	Start-Sleep -Seconds 120
	$compileJobHistory = @((Get-AzAutomationDscCompilationJob @targetParams | Where-Object {$_.StartTime -gt $jobTime}).Status )

	if ($compileJobHistory -contains "Running")
	{
		do
		{
			Write-Host "Waiting 4 minutes for compilation to complete..."
			Start-Sleep -Seconds 240
			$compileJobHistory = @((Get-AzAutomationDscCompilationJob @targetParams | Where-Object {$_.StartTime -gt $jobTime}).Status )
		} until ($compileJobHistory -notcontains "Running")
	}
	$compileJobHistory = @((Get-AzAutomationDscCompilationJob @targetParams | Where-Object {$_.StartTime -gt $jobTime}).Status )

	if ($compileJobHistory -contains "Suspended")
	{
		Write-Host "Failed jobs detected. Trying again..."
		$firstRun = $false
	}
} while ($compileJobHistory -contains "Suspended")

Write-Host "Configurations updated and deployed to all nodes."
