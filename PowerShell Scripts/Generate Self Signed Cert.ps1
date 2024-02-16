# This creates a self-signed cert with private key for the purpose of enterprise app registrations.
$applicationName = "SCuBA Gear"
$certPassword = "NewPasswordHere"
$certSplat = @{
    Subject = "CN=$applicationName"
    CertStoreLocation = 'Cert:\CurrentUser\My'
    KeyExportPolicy = 'Exportable'
    NotAfter = (Get-Date).AddYears(2)
    KeySpec = 'Signature'
    KeyLength = 2048
    KeyAlgorithm = 'RSA'
    HashAlgorithm = 'SHA256'
}
$myCert = New-SelfSignedCertificate @certSplat
$exportCertSplat = @{
    FilePath = $applicationName + ".pfx"
    Password = $(ConvertTo-SecureString -String $certPassword -AsPlainText -Force)
}
$myCert | Export-PfxCertificate @exportCertSplat
$myCert | Export-Certificate -FilePath $($applicationName + ".cer")
Write-Host "$applicationName certificate created. Your thumbprint is $(($myCert).Thumbprint)"
Write-Host "$((Get-ChildItem "$applicationName.cer").Name) and $((Get-ChildItem "$applicationName.pfx").Name) saved to $(Get-Location)."