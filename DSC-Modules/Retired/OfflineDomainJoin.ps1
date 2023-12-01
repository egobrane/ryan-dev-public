Configuration OfflineDomainJoin {

    #Currently just a test file - need a real file to test
    Import-DscResource -ModuleName ComputerManagementDSC

    Node 'localhost' {

        OfflineDomainJoin egobraneCOM
        {
            RequestFile = "C:\egobrane\OfflineDomainJoinTest.txt"
            IsSingleInstance = "Yes"
            DependsOn = "[Archive]DMZResource"
        }
    }
}