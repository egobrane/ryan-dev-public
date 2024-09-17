$principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users"
$taskName = "test vs code"
$time = New-ScheduledTaskTrigger -At 12:15 -Once
$description = "Updates VS Code, if it is not running and has not yet been updated."
$arg = '-noexit -Command "winget upgrade --id Microsoft.VisualStudioCode --custom ' + "'/VERYSILENT /MERGETASKS=!runcode'" + ' --accept-package-agreements --accept-source-agreements --disable-interactivity --force"'
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 23) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
Register-ScheduledTask -TaskName $taskName -Description $description -Trigger $time -Action $action -Principal $principal -Settings $settings -Force
Start-ScheduledTask -TaskName $taskName