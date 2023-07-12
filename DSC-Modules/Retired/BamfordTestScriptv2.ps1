Configuration BamfordTestScriptv2 {

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    $Cred = Get-AutomationPSCredential 'bamfordcred'

    Node 'localhost' {

        Script SymbolicGeocode
        {
            TestScript = {
                if (Test-Path -Path "C:\Testpath\seethis") {
                    $true }
                    else {
                        $false
                    }
                }  
            SetScript = {
                New-Item -ItemType SymbolicLink -Path "C:\Testpath\seethis" -Target "\\bamfordtestserv\DomainShare\canyouseeme\"
            }
            GetScript = {
                @{ Result = (Get-ChildItem "C:\Testpath\")}
            }
            PsDscRunAsCredential = $Cred
        }

    }
    
}
