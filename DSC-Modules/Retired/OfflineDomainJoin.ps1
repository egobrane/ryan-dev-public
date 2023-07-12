Configuration OfflineDomainJoin {

    #Currently just a test file - need a real file to test
    Import-DscResource -ModuleName ComputerManagementDSC

    Node 'localhost' {

        OfflineDomainJoin ACISSCOM
        {
            RequestFile = "C:\ACISS\OfflineDomainJoinTest.txt"
            IsSingleInstance = "Yes"
            DependsOn = "[Archive]DMZResource"
        }
    }
}