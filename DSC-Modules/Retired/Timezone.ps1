Configuration TimeZone {

    Import-DscResource -ModuleName ComputerManagementDSC

    Node 'localhost' {

        TimeZone EasternTime
        {
            IsSingleInstance = "Yes"
            TimeZone = "Eastern Standard Time"
        }
    }
}