# This script sets strict TLS transport headers in IIS

Add-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" -PSPath "IIS:\Sites\Default Web Site" -Name . -Value @{name = "Strict-Transport-Security"; value = "max-age=31536000; includeSubDomains" }

# This portion checks for the strict TLS transport headers in IIS

if ((Get-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders/add" -PSPath "IIS:\Sites\Default Web Site" -Name value |
Out-String -Stream) -like "*Strict-Transport-Security*")
{
	$true 
}
else
{
	$false 
}