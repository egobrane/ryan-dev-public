Configuration Registry {

    Node 'localhost' {

        Registry FIPSAlgorithmPolicy
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
            ValueName = "Enabled"
            ValueType = "Dword"
            ValueData = "1"
            Force = $true
        }

        Registry TerminalServer
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"
            ValueName = "fSingleSessionPerUser"
            ValueType = "Dword"
            ValueData = "0"
            Force = $true
        }

    }
}