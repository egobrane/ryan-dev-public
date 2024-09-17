#Test

if ((Get-DscLocalConfigurationManager).RefreshMode -ne "Pull" -and (Get-DscLocalConfigurationManager).ConfigurationMode -ne "ApplyAndAutoCorrect")
{
    $false
}
else
{
    $true
}
(Get-DscConfigurationStatus).Mode 
# if push, run config script to build and then
Set-DscLocalConfigurationManager .\Folder\

Remove-Item .\Folder\ -Recurse -Force -ErrorAction SilentlyContinue