using System.Xml.XPath;
/*
Random coinflip = new Random();
int flip1 = coinflip.Next(0, 2);
Console.WriteLine($"Dice roll! You flipped a {(flip1 == 0 ? "heads" : "tails")}");

// or

Random coin = new();
Console.WriteLine($"Dice roll again! You flipped a {((coin.Next(0, 2) == 0) ? "heads" : "tails")}");
*/

string permission = "Admsdfin|Manasdfager";
int level = 18;

if (permission.Contains("Admin"))
{
	if (level > 55)
	{
		Console.WriteLine("Welcome, Super Admin user.");
	}
	else if (level <= 55)
	{
		Console.WriteLine("Welcome, Admin user.");
	}
}
else if (permission.Contains("Manager"))
{
	if (level >= 20)
	{
		Console.WriteLine("Contact an Admin for acces.");
	}
	else if (level < 20)
	{
		Console.WriteLine("You do not have sufficient privileges.");
	}
}
else
{
	Console.WriteLine("You do not have any prileges dummy");
}