

$currentTimeZone = Get-TimeZone
$designatedTimeZone = 'Eastern Standard Time'
if ((Get-TimeZone).Id -eq 'Eastern Standard Time')
{
	$true
}
else {
	$false
}

@{ Result = (Get-TimeZone)}

(Get-TimeZone).Id

if ((Get-NetFirewallRule -DisplayGroup "Remote Desktop").Enabled -ne "False")
{
    $false
}
else
{
    $true
}

if ((Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue).Enabled -eq "False") {
    $false
}
    else {
    $true 
    }

Get-LocalGroupMember -Group "Administrators"


$group = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators"
    $admins = $group.Invoke('Members') | % {
        $path = ([adsi]$_).path
        [pscustomobject]@{
            Computer = $env:COMPUTERNAME
            Domain = $(Split-Path (Split-Path $path) -Leaf)
            User = $(Split-Path $path -Leaf)
        }
    }
foreach($admin in $admins){
   $admin
}

c
(Get-WmiObject Win32_ComputerSystem).Domain

(Get-TlsCipherSuite | Format-Table -HideTableHeaders).Count

#azCopy testing
$dsoRoot = 'C:\egobrane\$DevSecOps'
$azCopyDownloadUrl = "https://aka.ms/downloadazcopy-v10-windows"
$ProgressPreference = "SilentlyContinue"
$azCopyZipUrl = (Invoke-WebRequest -UseBasicParsing -Uri $azCopyDownloadUrl -MaximumRedirection 0 -ErrorAction SilentlyContinue).headers.location
$azCopyZipFile = Split-Path $azCopyZipUrl -leaf
$azCopyZipPath = Join-Path $dsoRoot $azCopyZipFile
$azCopyDir = Join-Path $dsoRoot "azcopy"
$azCopyPath = Join-Path $dsoRoot "azcopy.exe"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri $azCopyZipUrl -OutFile $azCopyZipPath
Expand-Archive -Path $azCopyZipPath -Destinationpath $azCopyDir -Force
$ProgressPreference = "Continue"

$azCopy = (Get-ChildItem -Path $azCopyDir -Recurse -File -Filter "azcopy.exe").FullName
Copy-Item $azCopy $azCopyPath

$azCopy


$indexPath = "C:\Users\ryan.bamford\Documents\Automation Project\Nightly Test Resources\nightlytestindex.htm"
if ((Test-Path -Path $indexPath) -and ((Get-Content -Path $indexPath |
	Out-String -Stream) -like "*./egobraneweb*")) {
		$true
	}
	else {
		$false
	}


$dsoStorageRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/Resources"

(& $azCopyPath login --identity --output-level="essential") | Out-Null
$result = (& $azCopyPath copy $dsoStorageRoot/nightlytestindex.htm "C:\Users\ryan.bamford\Documents\Automation Project\Nightly Test Resources\index.htm" --overwrite=true --output-level="essential") | Out-String
if($LASTEXITCODE -ne 0) {
	throw (("Copy error. $result"))
}


$dsoLocalResources = "C:\Users\ryan.bamford\Documents\Automation Project\Nightly Test Resources\"
(& $azCopyPath login --identity --output-level="essential") | Out-Null
$result = (& $azCopyPath copy "$dsoStorageRoot\ndp48-x86-x64-allos-enu.exe" "$dsoLocalResources\ndp48-x86-x64-allos-enu.exe" --output-level="essential") | Out-String
if($LASTEXITCODE -ne 0) {
	throw (("Copy error. $result"))
}
(& "$dsoLocalResources\ndp48-x86-x64-allos-enu.exe" /q)

@{ Result = (Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release)}


@{ Result = (Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name 'Version' -ErrorAction SilentlyContinue | ForEach-Object {$_.Version -as [System.Version]} | Where-Object {$_.Major -eq 3}) }


(Get-Item -Path "HKLM:\SOFTWARE\Microsoft\MSOLEDBSQL\InstalledVersion" -ErrorAction SilentlyContinue) -ne $null

$Path = "HKLM:\SOFTWARE\Microsoft\MSOLEDBSQL"

try {
Get-ItemPRoperty -Path $Path | Select-Object -ExpandProperty "Version" -ErrorAction Stop | Out-Null return $true }

catch {
return $false
}

Get-ChildItem -Path $Path


if ((Get-ItemProperty -Path $Path).InstalledVersion -ne $null) {
$true
}
else {
$false }

@{ Result = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\MSOLEDBSQL').InstalledVersion }

$dsoLocalResources = Join-Path $dsoRoot "Resources"
$msoledbsqlPath = Join-Path $dsoLocalResources "msoledbsql_18.6.5_x64_recommended.msi"
$dsoStorageRoot = "https://egobranemisc.blob.core.usgovcloudapi.net/devsecopsdev/scripts/DSC/Resources"
(& @azCopyPath login --identity --output-level="essential") | Out-Null
$result = (& $azCopyPath copy "$dsoStorageRoot\msoledbsql_18.6.5_x64_recommended.msi" `
$msoledbsqlPath --output-level="essential") |
Out-String
if($LASTEXITCODE -ne 0) {
	throw (("Copy error. $result"))
}

if ((Get-NetFirewallRule -DisplayGroup "File and Printer Sharing").Enabled -ne "True") {
$false
}
else {
    $true
    }

@{ Result = (Get-NetFirewallRule -DisplayGroup "File and Printer Sharing").DisplayName }



Get-Item WSMan:\localhost\Client\TrustedHosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
Clear-Item wsman:\localhost\client\trustedhosts 

if((Get-Item WSMan:\localhost\Client\TrustedHosts).Value -eq "*" -and `
(Get-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB).Value -eq "2147483647")
{
$true
}
else {
$false
}

@{ Result = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value}


Get-ExecutionPolicy

if ((Get-ExecutionPolicy) -eq "RemoteSigned") {
$true
}
else {
$false }

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

@{ Result = (Get-ExecutionPolicy)}



if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\MSOLEDBSQL' -ErrorAction SilentlyContinue).InstalledVersion -ne $null)
{
	$true
}
else
{
	$false
}

$hostNameTest = "egobraneWeb-v2-8-rel"
$hostName

@{ Result = (Get-WmiObject Win32_ComputerSystem).Domain}













{ $false}



$bibby = "Jingle.txt", "Krinkle.txt", "Single.txt"

$bibbycheck = (Get-ChildItem C:\Bibby -ErrorAction SilentlyContinue).Name

if ($bibby -contains $bibbycheck) {
    $true
    }
    else
    {
    $false
    }

if (@($bibby) -eq @($bibbycheck)) {
$true
}
else
{
$false
}

$areEqual = @(Compare-Object $bibby $bibbycheck -ErrorAction SilentlyContinue).Length -eq 0

$areEqual = @(Compare-Object -ReferenceObject @($bibby | Select-Object) `
-DifferenceObject @($bibbycheck | Select-Object)).Length -eq 0

$geocodePath = "C:\ProgramData\egobrane\egobraneWeb_Default\GeocodeData"

@{ Result = (Get-ChildItem C:\Bibby -ErrorAction SilentlyContinue)}


Test-Path "C:\Temp"

@{ Result = (Test-Path "C:\Temp")}

Get-Dsc

Configuration TestConfigName {

	param (
		[Parameter(Mandatory = $true)]
		[string]$hostName
	)

	#Import Desired DSC Modules - Must be present in Azure Automation
	Import-DscResource -ModuleName PSDesiredStateConfiguration

	$variableExample = "C:\Temp"

	Node $hostName {

		#Ensure Web-Server feature is present
		WindowsFeature WindowsFeatureName
		{
			Name = "Web-Server"
			Ensure = "Present"
		}

		#This is a script resource and can do anything powershell can do.
		Script ScriptResourceName
		{
			#TestScript must return boolean. If true, node is compliant. If false, runs SetScript
			TestScript = {
				#When calling variables outside of script resource, must use the using scope
				Test-Path $using:variableExample
			}
			SetScript = {
				New-Item -ItemType Directory -Path $using:variableExample
			}
			#GetScript is for diagnostics of a node and called upon with Get-DscLocalConfigurationManager
			GetScript = {
				@{ Result = (Test-Path $using:variableExample) }
			}
		}
	}
}

@{ Result = (Get-Item C:\Bibby\LogoffAnnounce.exe,C:\Bibby\LogonAnnounce.exe) }


Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'} | Format-Table

$intendedFeatures = @(
    'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
    'Rsat.DHCP.Tools~~~~0.0.1.0'
    'Rsat.Dns.Tools~~~~0.0.1.0'
    'Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0'
    'Rsat.FileServices.Tools~~~~0.0.1.0'
    'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
    'Rsat.ServerManager.Tools~~~~0.0.1.0'
    'Rsat.WSUS.Tools~~~~0.0.1.0'
    )


$currentFeatures = (Get-WindowsCapability -Name Rsat* -Online | Where-Object {$_.State -eq 'Installed'}).Name

$featureMatch = @(Compare-Object -ReferenceObject @($intendedFeatures | Select-Object) -DifferenceObject @($currentFeatures | Select-Object)).Length -eq 0

$featureMatch

$featureArray = @(
	'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
	'Rsat.DHCP.Tools~~~~0.0.1.0'
	'Rsat.Dns.Tools~~~~0.0.1.0'
	'Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0'
	'Rsat.FileServices.Tools~~~~0.0.1.0'
	'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
	'Rsat.ServerManager.Tools~~~~0.0.1.0'
	'Rsat.WSUS.Tools~~~~0.0.1.0'
)
foreach ($feature in $featureArray)
{
	Add-WindowsCapability -Online -Name $feature
}


if ('True' -in (Get-ScheduledTask -TaskName "egobrane Updates"))
{
$true
}
else
{
$false
}

if ((Get-ScheduledTask -TaskName "egobrane Updates" -ErrorAction SilentlyContinue).TaskName -eq "egobrane Updates")
{
$true
}
else
{
$false
}

@{ Result = (Get-ScheduledTask -TaskName "egobrane Updates" -ErrorAction SilentlyContinue) }



if (($env:AZCOPY_AUTO_LOGIN_TYPE) -eq "MSI")
{
$true
}
else
{
$false
}