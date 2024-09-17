$v = Get-Date -uformat %s;
$settings = @{
	"v" = $v;
};
$protectedSettings = @{
	"commandToExecute" = "powershell.exe Remove-Item -Path C:\egobraneS -Recurse -Force";
};
$machine = "Remote7";
Update-AzConnectedMachineExtension -Name "SecDevOps" -ResourceGroupName "egobrane-Internal" -MachineName $machine -Setting $settings -ProtectedSetting $protectedSettings -NoWait;