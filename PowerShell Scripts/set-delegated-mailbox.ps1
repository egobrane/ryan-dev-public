$targetMailbox = "customersupport@egobrane.com"
$grantedUser = "dilly@egobrane.com"

Connect-ExchangeOnline
Add-MailboxPermisssion -Identity $targetMailbox -user $grantedUser -AccessRights fullaccess 

Add-RecipientPermission -Identity $targetMailbox -AccessRights SendAs -Trustee $grantedUser

Set-Mailbox -Identity $targetMailbox -GrantSendOnBehalfTo ego.brane@egobrane.com

#verify permissions

Get-MailboxPermission -Identity $targetMailbox

Get-RecipientPermission -Identity $targetMailbox

Get-Mailbox -Identity $targetMailbox | Format-List GrantSendOnBehalfTo