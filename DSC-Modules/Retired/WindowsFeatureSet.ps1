Configuration WindowsFeatureSet {

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node 'localhost' {

        WindowsFeatureSet DMZNETFramework
        {
            Name = @(
                "NET-Framework-Features"
                "NET-Framework-Core"
                "NET-Framework-45-Features"
                "NET-Framework-45-Core"
                "NET-Framework-45-ASPNET"
                "NET-WCF-Services45"
                "NET-WCF-TCP-PortSharing"
                )
            Ensure = "Present"
        }

        WindowsFeatureSet DMZWebServer
        {
            Name = @(
                "Web-Server"
                "Web-WebServer"
                "Web-Common-Http"
                "Web-Default-Doc"
                "Web-Dir-Browsing"
                "Web-Http-Errors"
                "Web-Static-Content"
                "Web-Http-Redirect"
                "Web-Health"
                "Web-Http-Logging"
                "Web-Request-Monitor"
                "Web-Performance"
                "Web-Stat-Compression"
                "Web-Security"
                "Web-Filtering"
                "Web-Windows-Auth"
                "Web-App-Dev"
                "Web-Net-Ext45"
                "Web-Asp-Net45"
                "Web-Net-Ext"
                "Web-AppInit"
                "Web-ASP"
                "Web-Asp-Net"
                "Web-ISAPI-Ext"
                "Web-ISAPI-Filter"
                "Web-WebSockets"
                "Web-Mgmt-Tools"
                "Web-Mgmt-Console"
                )   
            Ensure = "Present"
        }

        WindowsFeatureSet DMZStorageServices
        {
            Name = @(
                "FileAndStorage-Services"
                "Storage-Services"
                )
            Ensure = "Present"
        }
    }
}