#This is an updated AutoUpdate script uploaded to devsecopsdev in Azure Storage to be used for DSC scripting to onboard devices to the AutoUpdate process.

param
(
	[bool]$logToEvent = $true,
	[bool]$logToConsole = $false
)

$settings =
@{
	executionDate = get-date -Format "yyyy-MM-dd HH:mm:ss";
	scriptVersion = "v1.0";
	scriptDescription = "This script will create/update a windows task for software updates.";
	dsoRoot = "C:\egobrane\cyberOps\";
	dsoStorageRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecops/";
	azCopyDownloadUrl = "https://aka.ms/downloadazcopy-v10-windows";
	azCopyPath = "";
	logEventId = 22470;
}

Set-StrictMode -Version latest;

$eventLogBuffer = [System.Text.StringBuilder]"";
function log
{
	param
	(
		[string]$message
	)

	if($logToEvent -eq $true) {$eventLogBuffer.AppendLine($message) | out-null;}
	if($logToConsole -eq $true) {Write-Host $message;}
}

function logFlush
{
	if($logToEvent -ne $true) {return;}
	Write-EventLog -LogName Application -Source "egobrane" -EntryType Information -Category 0 -EventID $settings.logEventId -Message $eventLogBuffer.ToString();
	$eventLogBuffer.Clear() | out-null;
}

log "";
log "Script: $($MyInvocation.MyCommand.Name)";
log "Execution Date: $($settings.executionDate)";
log "Script Version: $($settings.scriptVersion)";

log "";
log "Settings:";
log "Local DSO Root: $($settings.dsoRoot)";
log "Storage DSO Root: $($settings.dsoStorageRoot)";
log "";

function azCopyFile
{
	param
	(
		[string]$azCopyPath,
		[string]$src,
		[string]$dst
	)

	$srcFile = Split-Path $src -leaf;
	log "Copying '$($srcFile)'.";

	$env:AZCOPY_DISABLE_SYSLOG = "true";

	(& $azCopyPath login --identity --output-level="essential") | out-null;

	$result = (& $azCopyPath copy $src $dst --overwrite=ifSourceNewer --output-level="essential") | out-string;
	if($LASTEXITCODE -ne 0) {
		throw (("Copy error. $($result)"));
	}
}

# check event log source.
if([Diagnostics.EventLog]::SourceExists("egobrane") -eq $False) {
	New-EventLog -LogName Application -Source "egobrane" | out-null;
}

# update azcopy.
log "Checking for new azcopy.";
$ProgressPreference = "SilentlyContinue";
$azCopyZipUrl = (Invoke-WebRequest -UseBasicParsing -Uri $settings.azCopyDownloadUrl -MaximumRedirection 0 -ErrorAction SilentlyContinue).headers.location;
$azCopyZipFile = Split-Path $azCopyZipUrl -leaf;
$azCopyZipPath = Join-Path $settings.dsoRoot $azCopyZipFile;
$azCopyDir = Join-Path $settings.dsoRoot "azcopy";
$settings.azCopyPath = Join-Path $settings.dsoRoot "azcopy.exe";
if(-not (Test-Path $azCopyZipPath)) {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
	Invoke-WebRequest -UseBasicParsing -Uri $azCopyZipUrl -OutFile $azCopyZipPath;
	Expand-archive -Path $azCopyZipPath -Destinationpath $azCopyDir;
}
$ProgressPreference = "Continue";

$azCopy = (Get-ChildItem -path $azCopyDir -Recurse -File -Filter "azcopy.exe").FullName;
Copy-Item $azCopy $settings.azCopyPath;

# pull latest AutoUpdate.ps1 for next run.
$autoUpdatePath = (Join-Path $settings.dsoRoot "scripts/Update/AutoUpdate.ps1");
azCopyFile $settings.azcopyPath "https://egobranemisc.blob.core.usgovcloudapi.net/devsecops/scripts/Update/AutoUpdate.ps1" $autoUpdatePath;

# pull latest Update.ps1.
$updatePath = (Join-Path $settings.dsoRoot "scripts/Update/Update.ps1");
azCopyFile $settings.azcopyPath "https://egobranemisc.blob.core.usgovcloudapi.net/devsecops/scripts/Update/Update.ps1" $updatePath;

# update scheduled task.
log "Updating scheduled task.";
$name = "egobrane Updates";
$desc = "This task updates applications deployed by egobrane.";
$cmd = "powershell.exe";
$arg = ' -ExecutionPolicy Bypass -Command ". ' + $autoUpdatePath.replace('$', '`$') + ' -logToEvent $true; exit $LASTEXITCODE;"';
$trigger = New-ScheduledTaskTrigger -Daily -At 10pm;
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 23) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;
$action = New-ScheduledTaskAction -Execute $cmd -Argument $arg;
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $name -Description $desc -User "NT AUTHORITY\SYSTEM" -Settings $set -Force | out-null;

# run updates.
log "Update.ps1 running.";
log "------------------------------";
$result = (& $updatePath -reportOnly $false 6>&1 2>&1);
foreach($resultLine in ($result -split '\r?\n').Trim())
{
	log $resultLine;
}
log "------------------------------";
log "Update.ps1 complete.";

log "";
log "Done.";
log "";

logFlush;
