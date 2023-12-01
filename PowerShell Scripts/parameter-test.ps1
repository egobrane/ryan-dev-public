param(
	[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
	[Alias("VMName")]
	[string[]]$parameter1 = -Split $parameter1,

	[Alias("Target")]
	[ValidateSet("vm3.aad.egobrane.com", "vm4.aad.egobrane.com")]
	[string]$parameter2
)

$parameter2 = Read-Host -Prompt "Please enter target system, or leave blank for default"

if (($parameter2 -eq 'vm3.aad.egobrane.com') -or ($parameter2 -eq 'vm4.aad.egobrane.com'))
{
	Write-Host "Target Host set to $parameter2"
}
else
{
	Write-Host "Target Host not valid. Please enter vm3.aad.egobrane.com or vm4.aad.egobrane.com"
	Break
}

foreach ($parameter in $parameter1)
{
	Write-Host "Value of the first parameter is $parameter"
	Write-Host "Value of the second parameter is $parameter2"
}
