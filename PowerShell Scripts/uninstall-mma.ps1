$app = Get-WmiObject -ClassName Win32_Product | Where-Object { $_.name -eq "Microsoft Monitoring Agent" }
$app.Uninstall()