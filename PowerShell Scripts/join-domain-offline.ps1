# There is some definite fuckery going on here
# This gets a djoin.txt file from Azure Key Vault, downloads it and applies it.
# The ending character in a djoin.txt file is a null value
# Copying the txt into Azure Key vault changes this to an empty string 
# This script cuts off the bytes from the empty string, creates a null payload of bytes, and adds it back to the end of the file
# The djoin.txt file can then be successfully applied.

# This script authenticates to Azure with machine identity

param (
	[Parameter(Mandatory=$true)]
	[string]$hostName = "dmz-test",

	[Parameter(Mandatory=$true)]
	[string]$localStorageRoot = "C:\Temp\"
)

if (!(Get-PackageProvider -Name "Nuget" -ErrorAction SilentlyContinue))
{
	Install-PackageProvider -Name Nuget
}
if (!(Get-InstalledModule -Name "Az.Accounts" -ErrorAction SilentlyContinue))
{
	Install-Module Az.Accounts -Force
}
if (!(Get-InstalledModule -Name "Az.KeyVault" -ErrorAction SilentlyContinue))
{
	Install-Module Az.KeyVault -Force
}
do
{
	Connect-AzAccount -Scope Process -Identity
} until (Get-AzTenant)

$odjBody = Get-AzKeyVaultSecret -VaultName "key-vault" -Name "djoin-$hostName" -AsPlainText
Set-Content -Path "$localStorageRoot\ODJ.txt" -value $odjBody -Encoding Unicode
$bytes = [System.IO.File]::ReadAllBytes("$localStorageRoot\ODJ.txt")
[System.IO.File]::WriteAllBytes("C:\Temp\odj3.txt",$bytes[0..($bytes.length-3)])
[Byte[]] $startingBytes = Get-Content -Path "$localStorageRoot\ODJ.txt" -Encoding Byte
[Byte[]] $payload = 0x00,0x00
[Byte[]] $outBytes = $startingBytes + $payload
Set-Content -Path "$localStorageRoot\ODJ.txt" -Value $outBytes -Encoding Byte
djoin.exe --% /requestodj /psite "DmzHQ" /loadfile "$localStorageRoot\ODJ.txt" /windowspath %systemroot% /localos

Remove-Item "$localStorageRoot\ODJ.txt" -Force