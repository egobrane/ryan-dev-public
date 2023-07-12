Configuration User {

    #variable for acissla password is present in automation at this time
    Node 'localhost' {

        User acissla
        {
            Ensure = "Present"
            Disabled = $false
            UserName = "acissla"
            FullName = "acissla"
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