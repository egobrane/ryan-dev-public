# Connect to AzAccount, and AzureAD, because it gets confused with multiple tenants and users if the context is not correct
Connect-AzAccount -Tenant 204a8dcb-68e2-4947-95a8-ed313d75b397 
Connect-AzureAD -TenantId 204a8dcb-68e2-4947-95a8-ed313d75b397

$results = @()
Get-AzureADApplication -All $true | ForEach-Object {  
	$app = $_
	$app.PasswordCredentials | 
	ForEach-Object { 
		$results += [PSCustomObject] @{
			CredentialType = "Client Secrets"
			DisplayName    = $app.DisplayName; 
			ExpiryDate     = $_.EndDate;
			StartDate      = $_.StartDate;
			KeyID          = $_.KeyId;
		}
	}               
}
$results | Sort-Object { $_.ExpiryDate } | Format-Table -AutoSize 