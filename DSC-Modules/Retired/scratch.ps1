Configuration Sample_WebConfigProperty_Add
{
    param
    (
        # Target nodes to apply the configuration.
        [Parameter()]
        [String[]]
        $NodeName = 'localhost'
    )

    # Import the modules that define custom resources
    Import-DscResource -ModuleName WebAdministrationDsc

    Node $NodeName
    {
        WebConfigProperty "$($NodeName) - Ensure 'directory browsing' is set to disabled - Add"
        {
            WebsitePath  = 'IIS:\Sites\Default Web Site'
            Filter       = 'system.webServer/directoryBrowse'
            PropertyName = 'enabled'
            Value        = 'false'
            Ensure       = 'Present'
        }
    }
}