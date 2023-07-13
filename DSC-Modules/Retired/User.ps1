Configuration User {

    #variable for localadmin password is present in automation at this time
    Node 'localhost' {

        User localadmin
        {
            Ensure = "Present"
            Disabled = $false
            UserName = "localadmin"
            FullName = "localadmin"
            Password = $testcred
            PasswordChangeRequired = $false
            PasswordNeverExpires = $true
        }

        User Administrator
        {
            Ensure = "Present"
            Disabled = $true
            UserName = "Administrator"
        }
    }
}