# all vms
# all remotes, management
# dmz actually gets server 

$secretHash = @{

}

$hostNames = @(

)

foreach ($hostName in $hostNames)
{
    $secretValue = ConvertTo-SecureString ($secretHash[$hostName]) -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName "dsc-config-vault" -Name $hostName -SecretValue $secretValue
}