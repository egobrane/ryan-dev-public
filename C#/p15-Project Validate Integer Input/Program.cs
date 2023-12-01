int numericValue = 0;
bool validNumber = false;
string? readResult;
string valueEntered = "";

Console.WriteLine("Please enter an integer between 5 and 10");

do
{
	readResult = Console.ReadLine();
	if (readResult != null)
	{
		valueEntered = readResult;
	}
	validNumber = int.TryParse(readResult, out numericValue);

	if (validNumber == true)
	{
		if (numericValue <= 5 || numericValue >= 10)
		{
			validNumber = false;
			Console.WriteLine($"You entered {numericValue}. Please enter a number between 5 and 10.");
		}
	}
	else
	{
		Console.WriteLine("Sorry, you entered an invalid number, please try again");
	}
} while (validNumber == false);

Console.WriteLine($"Your input value ({numericValue}) has been accepted.");

