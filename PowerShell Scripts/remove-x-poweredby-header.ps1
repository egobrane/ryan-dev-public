# This script removes the X-Powered-By header from IIS

Clear-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']"

# This portion tests the removal of X-Powered-By

if ((Get-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']").Name -like 'X-Powered-By')
{
	$false 
}
else
{
	$true 
}    