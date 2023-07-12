configuration Hypervisorv5
{
    Import-DscResource -ModuleName "ComputerManagementDSC"
	
	node "localhost"
    {
      WindowsFeature Hyper-V {
            Ensure = "Present"
            Name = "Hyper-V"
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