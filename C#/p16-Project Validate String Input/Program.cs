string? userEntry;
string roleName = "";
bool validEntry = false;

Console.WriteLine("Enter your role name (Administrator, Manager, or User)");

/*
while (validEntry == false)
{
	userEntry = Console.ReadLine();
	if (userEntry != null)
	{
		userEntry.Trim().ToLower();
		if ((userEntry == "Administrator") || (userEntry == "Manager") || (userEntry == "User"))
		{
			Console.WriteLine($"Your input value ({userEntry}) has been accepted.");
			validEntry = true;
		}
		else
		{
			Console.WriteLine($"The role name that you entered, \"{userEntry}\" is not valid. Enter your role name (Administrator, Manager, or User)");
		}
	}
}
*/
while (validEntry == false)
{
	userEntry = Console.ReadLine();
	if (userEntry != null)
	{
		roleName = userEntry.Trim();
	}

	if (roleName.ToLower() == "administrator" || roleName.ToLower() == "manager" || roleName.ToLower() == "user")
	{
		validEntry = true;
	}
	else
	{
		Console.Write($"The role name that you entered, \"{roleName}\" is not valid. ");
	}
}

Console.WriteLine($"Your input value ({roleName}) has been accepted.");
