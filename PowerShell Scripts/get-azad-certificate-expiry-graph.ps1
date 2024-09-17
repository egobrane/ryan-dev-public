Connect-MgGraph -Scopes 'Application.Read.All'

$Messages = @{
    ExpirationDays = @{
        Info   = 'Filter the applications to log by the number of days until their secrets expire.'
        Prompt = 'Enter the number of days until the secrets expire as an integer.'
    }
    AlreadyExpired = @{
        Info   = 'Would you like to see Applications with already expired secrets as well?'
        Prompt = 'Enter Yes or No'
    }
    DurationNotice = @{
        Info = @(
            'The operation is running and will take longer the more applications the tenant has...'
            'Please wait...'
        ) -join ' '
    }
    Export = @{
        Info = 'Where should the CSV file export to?'
        Prompt = 'Enter the full path in the format of <C:\Users\<USER>\Desktop\Users.csv>'
    }
}

Write-Host $Messages.ExpirationDays.Info -ForegroundColor Green
$DaysUntilExpiration = Read-Host -Prompt $Messages.ExpirationDays.Prompt

Write-Host $Messages.AlreadyExpired.Info -ForegroundColor Green
$IncludeAlreadyExpired = Read-Host -Prompt $Messages.AlreadyExpired.Prompt

$Now = Get-Date

Write-Host $Messages.DurationNotice.Info -ForegroundColor yellow

$Applications = Get-MgApplication -all

$Logs = @()

foreach ($App in $Applications) {
    $AppName = $App.DisplayName
    $AppID   = $App.Id
    $ApplID  = $App.AppId

    $AppCreds = Get-MgApplication -ApplicationId $AppID |
        Select-Object PasswordCredentials, KeyCredentials

    $Secrets = $AppCreds.PasswordCredentials
    $Certs   = $AppCreds.KeyCredentials

    foreach ($Secret in $Secrets) {
        $StartDate  = $Secret.StartDateTime
        $EndDate    = $Secret.EndDateTime
        $SecretName = $Secret.DisplayName

        $Owner    = Get-MgApplicationOwner -ApplicationId $App.Id
        $Username = $Owner.AdditionalProperties.userPrincipalName -join ';'
        $OwnerID  = $Owner.Id -join ';'

        if ($null -eq $Owner.AdditionalProperties.userPrincipalName) {
            $Username = @(
                $Owner.AdditionalProperties.displayName
                '**<This is an Application>**'
            ) -join ' '
        }
        if ($null -eq $Owner.AdditionalProperties.displayName) {
            $Username = '<<No Owner>>'
        }

        $RemainingDaysCount = ($EndDate - $Now).Days

        if ($IncludeAlreadyExpired -eq 'No') {
            if ($RemainingDaysCount -le $DaysUntilExpiration -and $RemainingDaysCount -ge 0) {
                $Logs += [PSCustomObject]@{
                    'ApplicationName'        = $AppName
                    'ApplicationID'          = $ApplID
                    'Secret Name'            = $SecretName
                    'Secret Start Date'      = $StartDate
                    'Secret End Date'        = $EndDate
                    'Certificate Name'       = $Null
                    'Certificate Start Date' = $Null
                    'Certificate End Date'   = $Null
                    'Owner'                  = $Username
                    'Owner_ObjectID'         = $OwnerID
                }
            }
        } elseif ($IncludeAlreadyExpired -eq 'Yes') {
            if ($RemainingDaysCount -le $DaysUntilExpiration) {
                $Logs += [PSCustomObject]@{
                    'ApplicationName'        = $AppName
                    'ApplicationID'          = $ApplID
                    'Secret Name'            = $SecretName
                    'Secret Start Date'      = $StartDate
                    'Secret End Date'        = $EndDate
                    'Certificate Name'       = $Null
                    'Certificate Start Date' = $Null
                    'Certificate End Date'   = $Null
                    'Owner'                  = $Username
                    'Owner_ObjectID'         = $OwnerID
                }
            }
        }
    }

    foreach ($Cert in $Certs) {
        $StartDate = $Cert.StartDateTime
        $EndDate   = $Cert.EndDateTime
        $CertName  = $Cert.DisplayName

        $Owner    = Get-MgApplicationOwner -ApplicationId $App.Id
        $Username = $Owner.AdditionalProperties.userPrincipalName -join ';'
        $OwnerID  = $Owner.Id -join ';'

        if ($null -eq $Owner.AdditionalProperties.userPrincipalName) {
            $Username = @(
                $Owner.AdditionalProperties.displayName
                '**<This is an Application>**'
            ) -join ' '
        }
        if ($null -eq $Owner.AdditionalProperties.displayName) {
            $Username = '<<No Owner>>'
        }

        $RemainingDaysCount = ($EndDate - $Now).Days

        if ($IncludeAlreadyExpired -eq 'No') {
            if ($RemainingDaysCount -le $DaysUntilExpiration -and $RemainingDaysCount -ge 0) {
                $Logs += [PSCustomObject]@{
                    'ApplicationName'        = $AppName
                    'ApplicationID'          = $ApplID
                    'Secret Name'            = $Null
                    'Certificate Name'       = $CertName
                    'Certificate Start Date' = $StartDate
                    'Certificate End Date'   = $EndDate
                    'Owner'                  = $Username
                    'Owner_ObjectID'         = $OwnerID
                }
            }
        } elseif ($IncludeAlreadyExpired -eq 'Yes') {
            if ($RemainingDaysCount -le $DaysUntilExpiration) {
                $Logs += [PSCustomObject]@{
                    'ApplicationName'        = $AppName
                    'ApplicationID'          = $ApplID
                    'Secret Name'            = $Null
                    'Certificate Name'       = $CertName
                    'Certificate Start Date' = $StartDate
                    'Certificate End Date'   = $EndDate
                    'Owner'                  = $Username
                    'Owner_ObjectID'         = $OwnerID
                }
            }
        }
    }
}

$Logs