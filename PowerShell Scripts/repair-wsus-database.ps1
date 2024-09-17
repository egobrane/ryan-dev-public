# this is ozempic for a WSUS database
Get-WSUSUpdate -Classification All -Status Any -Approval AnyExceptDeclined |
Where-Object { $_.Update.GetRelatedUpdates(([Microsoft.UpdateServices.Administration.UpdateRelationship]::UpdatesThatSupersedeThisUpdate)).Count -gt 0 } |
Deny-WsusUpdate

Invoke-WsusServerCleanup -CleanupObsoleteUpdates -CleanupUnneededContentFiles