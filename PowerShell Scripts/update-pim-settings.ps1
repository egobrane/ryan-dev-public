#This script updates the PIM settings for a given Entra Role or Group

param
(
	[string]$roleName = "",
	[string]$emailRecipient = "operations@aciss.com"
)
# Connect to MS Graph, needs privileged role admin or global admin
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory", "RoleManagementPolicy.ReadWrite.AzureADGroup" -ContextScope Process

$azureRoles = Get-MgDirectoryRoleTemplate | Select-Object DisplayName, Description, Id | Sort-Object DisplayName
$azureGroups = Get-MgGroup | Select-Object DisplayName, Description, Id | Sort-Object DisplayName

# get policy assignment for a role 
if ($azureRoles.DisplayName -contains $roleName) 
{
	
	$policyAssignment = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$(($azureRoles |
		Where-Object DisplayName -eq $roleName).Id)'" -ExpandProperty "policy(`$expand=rules)"
	Write-Host "Azure Role detected."
}
elseif ($azureGroups.DisplayName -contains $roleName)
{
	$groupId = (Get-MgGroup | Where-Object {$_.DisplayName -eq $roleName}).Id
	$policyAssignment = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '$($groupId)' and scopeType eq 'Group' and roleDefinitionId eq 'member'" `
		-ExpandProperty "policy(`$expand=rules)"
	Write-Host "Azure Group detected."
}
else
{
	throw ("Provided group not identified as a valid Role or Group. Please check spelling and try again.")
	return
}
# get policy for assignment
$policy = Get-MgPolicyRoleManagementPolicy -UnifiedRoleManagementPolicyId $policyAssignment.PolicyId

# LIST EXISTING RULES!! not necessary to run script, purely informational
# get rules for policy
#$policyRules = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id
# Sort Rule Ids
#$policyRules | Select-Object Id | Sort-Object ID
#finally, list specific settings
#foreach ($rule in ($policyRules | Sort-Object Id)) {
#	Write-Host "------------"
#	$Rule.Id
#	Write-Host ""
#	$Rule.ToJsonString()
#}

# UPDATE RULES!!
Write-Host "Updating Rules for $roleName"
Write-Host "----------------------------"

Write-Host "Configure Rule: Expiration_EndUser_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
	Id = "Expiration_EndUser_Assignment"
	isExpirationRequired = $false
	maximumDuration = "PT8H"
	Target = @{
		"@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
		Caller = "EndUser"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Expiration_EndUser_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Enablement_EndUser_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
	Id = "Enablement_EndUser_Assignment"
	enabledRules = "MultiFactorAuthentication", "Justification"
	Target = @{
		"@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
		Caller = "EndUser"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Enablement_EndUser_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: AuthenticationContext_EndUser_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule"
	Id = "AuthenticationContext_EndUser_Assignment"
	isEnabled = $false
	claimValue = ""
	Target = @{
		"@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
		Caller = "EndUser"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'AuthenticationContext_EndUser_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Approval_EndUser_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"
	id = "Approval_EndUser_Assignment"
	target = @{
		"@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
		caller = "EndUser"
		operations = @(
			"All"
		)
		level = "Assignment"
		inheritableSettings = @(
		)
		enforcedSettings = @(
		)
	}
	setting = @{
		"@odata.type" = "microsoft.graph.approvalSettings"
		isApprovalRequired = $false
		isApprovalRequiredForExtension = $false
		isRequestorJustificationRequired = $true
		approvalMode = "SingleStage"
		approvalStages = @(
			@{
				"@odata.type" = "microsoft.graph.unifiedApprovalStage"
				approvalStageTimeOutInDays = 1
				isApproverJustificationRequired = $true
				escalationTimeInMinutes = 0
				primaryApprovers = @(
				)
				isEscalationEnabled = $false
				escalationApprovers = @(
				)
			}
		)
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Approval_EndUser_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Expiration_Admin_Eligibility..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
	Id = "Expiration_Admin_Eligibility"
	isExpirationRequired = $false
	maximumDuration = "P365D"
	Target = @{
		"@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
		Caller = "Admin"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Eligibility"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Expiration_Admin_Eligibility' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Expiration_Admin_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
	Id = "Expiration_Admin_Assignment"
	isExpirationRequired = $false
	maximumDuration = "P180D"
	Target = @{
		"@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
		Caller = "Admin"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Expiration_Admin_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Enablement_Admin_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
	Id = "Enablement_Admin_Assignment"
	enabledRules = @("Justification")
	Target = @{
		"@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
		Caller = "Admin"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Enablement_Admin_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Enablement_EndUser_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
	Id = "Enablement_EndUser_Assignment"
	enabledRules = @("MultiFactorAuthentication", "Justification")
	Target = @{
		"@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
		Caller = "EndUser"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Enablement_EndUser_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Notification_Admin_Admin_Eligbility..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
	Id = "Notification_Admin_Admin_Eligbility"
	notificationType = "Email"
	recipientType = "Admin"
	notificationLevel = "All"
	isDefaultRecipientsEnabled = $false
	notificationRecipients = @($emailRecipient)
	Target = @{
		"@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
		Caller = "Admin"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Eligibility"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Notification_Admin_Admin_Eligibility' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Notification_Requestor_Admin_Eligibility..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
	Id = "Notification_Requestor_Admin_Eligibility"
	notificationType = "Email"
	recipientType = "Requestor"
	notificationLevel = "All"
	isDefaultRecipientsEnabled = $false
	notificationRecipients = @()
	Target = @{
		Caller = "Admin"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Eligibility"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Notification_Requestor_Admin_Eligibility' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Notification_Approver_Admin_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
	Id = "Notification_Approver_Admin_Assignment"
	notificationType = "Email"
	recipientType = "Approver"
	notificationLevel = "All"
	isDefaultRecipientsEnabled = $true
	notificationRecipients = @()
	Target = @{
		Caller = "Admin"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Notification_Approver_Admin_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Notification_Admin_Admin_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
	Id = "Notification_Admin_Admin_Assignment"
	notificationType = "Email"
	recipientType = "Admin"
	notificationLevel = "All"
	isDefaultRecipientsEnabled = $true
	notificationRecipients = @($emailRecipient)
	Target = @{
		Caller = "Admin"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Notification_Admin_Admin_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Notification_Requestor_Admin_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
	Id = "Notification_Requestor_Admin_Assignment"
	notificationType = "Email"
	recipientType = "Requestor"
	notificationLevel = "All"
	isDefaultRecipientsEnabled = $false
	notificationRecipients = @()
	Target = @{
		Caller = "Admin"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Notification_Requestor_Admin_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Notification_Approver_Admin_Eligibility..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
	Id = "Notification_Approver_Admin_Eligibility"
	notificationType = "Email"
	recipientType = "Approver"
	notificationLevel = "All"
	isDefaultRecipientsEnabled = $true
	notificationRecipients = @()
	Target = @{
		Caller = "Admin"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Eligibility"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Notification_Approver_Admin_Eligibility' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Notification_Admin_EndUser_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
	Id = "Notification_Admin_EndUser_Assignment"
	notificationType = "Email"
	recipientType = "Admin"
	notificationLevel = "All"
	isDefaultRecipientsEnabled = $false
	notificationRecipients = @($emailRecipient)
	Target = @{
		Caller = "EndUser"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Notification_Admin_EndUser_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Notification_Requestor_EndUser_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
	Id = "Notification_Requestor_EndUser_Assignment"
	notificationType = "Email"
	recipientType = "Requestor"
	notificationLevel = "All"
	isDefaultRecipientsEnabled = $false
	notificationRecipients = @()
	Target = @{
		Caller = "EndUser"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Notification_Requestor_EndUser_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Configure Rule: Notification_Approver_EndUser_Assignment..."
$params = @{
	"@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
	Id = "Notification_Approver_EndUser_Assignment"
	notificationType = "Email"
	recipientType = "Approver"
	notificationLevel = "All"
	isDefaultRecipientsEnabled = $true
	notificationRecipients = @()
	Target = @{
		Caller = "EndUser"
		EnforcedSettings = @()
		InheritableSettings = @()
		Level = "Assignment"
		Operations = @("all")
	}
}
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -UnifiedRoleManagementPolicyRuleId 'Notification_Approver_EndUser_Assignment' -BodyParameter $params
Write-Host "...done."
Write-Host "-----------------------------"

Write-Host "Updating PIM Settings for $roleName complete."