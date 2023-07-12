Configuration WindowsFeature {

    Node 'localhost' {

        WindowsFeature NET-Framework-45-Core
        {
            Name = "NET-Framework-45-Core"
            Ensure = "Present"
        }

 
        
    }
}