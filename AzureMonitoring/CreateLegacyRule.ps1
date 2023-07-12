$source = New-AzScheduledQueryRuleSource -Query 'Syslog | where TimeGenerated > ago (60m) | union (Syslog | sort by TimeGenerated desc | limit 1)' -DataSourceId "/subscriptions/SUBID/resourceGroups/GROUPID/providers/Microsoft.OperationalInsights/workspaces/WORKSPACEID"
$schedule = New-AzScheduledQueryRuleSchedule -FrequencyInMinutes 5 -TimeWindowInMinutes 5
$metricTrigger = New-AzScheduledQueryRuleLogMetricTrigger -ThresholdOperator "GreaterThan" -Threshold 0 -MetricTriggerType "Consecutive" -MetricColumn "_ResourceId"
$triggerCondition = New-AzScheduledQueryRuleTriggerCondition -ThresholdOperator "GreaterThan" -Threshold 0 -MetricTrigger $metricTrigger
$aznsActionGroup = New-AzScheduledQueryRuleAznsActionGroup -ActionGroup "/subscriptions/SUBID/resourceGroups/GROUPID/providers/microsoft.insights/actiongroups/ryantest" -EmailSubject "No Syslogs for at least 60 minutes"
$alertingAction = New-AzScheduledQueryRuleAlertingAction -AznsAction $aznsActionGroup -Severity "1" -Trigger $triggerCondition
New-AzScheduledQueryRule -ResourceGroupName "GroupName" -Location "East US" -Action $alertingAction -Enabled $true -Description "Alert description" -Schedule $schedule -Source $source -Name "No Syslogs Received"

# GreaterThan, LessThan, EqualTo