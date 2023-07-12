Configuration RemoteDesktopAdmin {

    Import-DscResource -ModuleName ComputerManagementDSC

    Node 'localhost' {

        RemoteDesktopAdmin RemoteDesktopSettings
        {
            IsSingleInstance = "Yes"
            Ensure = "Present"
            UserAuthentication = "Secure"
        }
    }
}