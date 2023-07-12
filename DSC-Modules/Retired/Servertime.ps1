configuration ServerTime
{
    Import-DscResource -ModuleName "ComputerManagementDSC"
    Import-DscResource -ModuleName "PSDesiredStateConfiguration"
	
	node "localhost"
    {

	  TimeZone ServerTime{
	  	    TimeZone = "Eastern Standard Time"
		    IsSingleInstance = "yes"
	    }

	}
}