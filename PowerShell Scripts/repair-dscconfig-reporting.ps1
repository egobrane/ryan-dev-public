[DSCLocalConfigurationManager()]
configuration LCMConfig
{
    Node localhost
    {
        Settings
        {
            RefreshMode = 'Pull'
            ConfigurationMode = 'ApplyAndAutoCorrect'
        }
        ConfigurationRepositoryWeb AzureAutomationStateConfiguration
        {
            ServerUrl = 'https://######.agentsvc.usge.azure-automation.us/accounts/egobrane'
        }
        ResourceRepositoryWeb AzureAutomationStateConfiguration
        {
            ServerUrl = 'https://egobrane.agentsvc.usge.azure-automation.us/accounts/egobrane'
        }
        ReportServerWeb AzureAutomationStateConfiguration
        {
            ServerUrl = 'https://egobrane.agentsvc.usge.azure-automation.us/accounts/egobrane'
        }
    }
}

LCMConfig 
