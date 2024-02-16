# This script sets file and folder permissions for a given directory. It leaves exceptions for Authenticated users to read and execute the files
# It also sets admin access to SYSTEM for automation processes to work.

param (
	[Parameter(Mandatory=$true)]
	[string]$targetFolder = ""
)

$userSYSTEM = "NT AUTHORITY\SYSTEM"
$groupAuthenticatedUsers = "NT AUTHORITY\Authenticated Users"

#Set SYSTEM Full access and ownership
$acl = Get-Acl -Path $targetFolder
$accessRuleSYSTEM = New-Object System.Security.AccessControl.FileSystemAccessRule ($userSYSTEM, "FullControl,TakeOwnership,ChangePermissions", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRuleSYSTEM)
$acl | Set-Acl -Path $targetFolder
icacls.exe $targetFolder /setowner $userSYSTEM /t

#Disable inheritance
$acl.SetAccessRuleProtection($true, $false)
$acl | Set-Acl -Path $targetFolder

#Remove extra explicit permissions
$fileTree = @((Get-ChildItem -Path $targetFolder -Recurse | Select-Object FullName).FullName) + @($targetFolder)
foreach ($file in $fileTree)
{
	[System.Collections.ArrayList]$identityArray = $identityArray + @((Get-Acl -Path $file).Access.IdentityReference.Value)
}

while (($identityArray -contains $groupAuthenticatedUsers) -or ($identityArray -contains $userSYSTEM))
{
	$identityArray.Remove($groupAuthenticatedUsers)
	$identityArray.Remove($userSYSTEM)
}

foreach ($file in $fileTree)
{
	[array]$identitySearch = (Get-Acl -Path $file).Access.IdentityReference.Value
	if (($identitySearch | ForEach-Object{ $identityArray.Contains($_) }) -contains $true)
	{
		foreach ($identity in $identityArray)
		{
			$userSID = New-Object System.Security.Principal.NTAccount ($identity)
			$acl.PurgeAccessRules($userSID)
			$acl | Set-Acl -Path $file
		}
	}
}

#Set Authenticated Users read and execute access
$accessRuleAuthenticatedUsers = New-Object System.Security.AccessControl.FileSystemAccessRule ($groupAuthenticatedUsers, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRuleAuthenticatedUsers)
$acl | Set-Acl -Path $targetFolder

#Set SYSTEM ownership on root
icacls.exe $targetFolder /setowner $userSYSTEM


#####################
# This portion tests to make sure the permissions are implemented

$desiredACLAssignments = @(
	'NT AUTHORITY\Authenticated Users'
	'NT AUTHORITY\SYSTEM'
)
$desiredACLPermissions = @(
	'ReadAndExecute, Synchronize'
	'FullControl'
)

$fileTree = @((Get-ChildItem -Path $targetFolder -Recurse | Select-Object FullName).FullName) + @($targetFolder)
foreach ($file in $fileTree)
{
	[Array]$ACLAssignments = @(($ACLAssignments) + (((Get-Acl -Path $file).Access.IdentityReference | Sort-Object Value).Value))
	[Array]$ACLPermissions = @(($ACLPermissions) + (((Get-Acl -Path $file).Access | Sort-Object FileSystemRights).FileSystemRights))
}
$currentACLAssignments = $ACLAssignments | Select-Object -Unique
$currentACLPermissions = $ACLPermissions | Select-Object -Unique

$assignmentMatch = @(Compare-Object -ReferenceObject @($desiredACLAssignments | Select-Object) `
		-DifferenceObject @($currentACLAssignments | Select-Object)).Length -eq 0 | Out-String -Stream
$permissionMatch = @(Compare-Object -ReferenceObject @($desiredACLPermissions | Select-Object) `
		-DifferenceObject @($currentACLPermissions | Select-Object)).Length -eq 0 | Out-String -Stream

if (($assignmentMatch -eq 'True') -and ($permissionMatch -eq 'True'))
{
	$true
}
else
{
	$false
}