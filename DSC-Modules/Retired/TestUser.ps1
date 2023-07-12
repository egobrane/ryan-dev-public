configuration TestUser
{
    Import-DscResource -ModuleName "ComputerManagementDSC"
    Import-DscResource -ModuleName "PSDesiredStateConfiguration"
	
	node "localhost"
    {

	  TimeZone ServerTime{
	  	    TimeZone = "Eastern Standard Time"
		    IsSingleInstance = "yes"
	    }

        User TestUser{
            Ensure = "Present"
            UserName = "testuser"
            Password = $testcred
            FullName = "Test User"
            PasswordNeverExpires = $true
            PasswordChangeRequired = $false
        }


	}
}