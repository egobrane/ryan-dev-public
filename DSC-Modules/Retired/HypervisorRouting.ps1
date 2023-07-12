configuration HypervisorRouting
{
    Import-DscResource -ModuleName "ComputerManagementDSC"
    Import-DscResource -ModuleName "PSDesiredStateConfiguration"
	
	node "localhost"
    {
      WindowsFeature Hyper-V {
            Ensure = "Present"
            Name = "Hyper-V"
		    IncludeAllSubFeature = $true
        }
	
	  WindowsFeature RemoteAccess {
			Ensure = "Present"
			Name = "Routing"
			IncludeAllSubFeature = $true
	  	}
		
	  WindowsFeature RSAT-Hyper-V-Tools {
            Name = "RSAT-Hyper-V-Tools"
            Ensure = "Present"
            IncludeAllSubFeature = $true
        }

	  TimeZone ServerTime{
	  	    TimeZone = "Eastern Standard Time"
		    IsSingleInstance = "yes"
	    }

	  RemoteDesktopAdmin RemoteDeskopSettings {
	  	    Ensure = "Present"
		    UserAuthentication = "secure"
		    IsSingleInstance = "yes"
        }

	  File VMs {
		    Ensure = "Present"
		    Type = "Directory"
		    DestinationPath = "$($env:SystemDrive)\VMs"
    	}
	}
}