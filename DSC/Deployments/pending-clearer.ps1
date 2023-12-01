Configuration PendingClear {


	Import-DscResource -ModuleName PSDesiredStateConfiguration 

	Node localhost {

		File ClearPending
		{
			Ensure = "Absent"
			DestinationPath = "C:\Pending"
			Type = "Directory"
		}
	}
}