$CimParameters = @{
    ClassName = 'Msft_Providers'
    Filter    = "provider='dsctimer' OR provider='dsccore'"
}
$dscProcessID = Get-CimInstance @CimParameters |
    Select-Object -ExpandProperty HostProcessIdentifier

###
### Stop the process
###
Get-Process -Id $dscProcessID | Stop-Process

Start-DscConfiguration -UseExisting -Verbose -Wait