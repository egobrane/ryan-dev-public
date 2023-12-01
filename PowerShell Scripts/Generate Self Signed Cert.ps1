#Create Certificate

$certname = "M365DSC Certificate"
$cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable `
	-KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA512

	
#Export .Cer

Export-Certificate -Cert $cert -FilePath "C:\SSL\$certname.cer"