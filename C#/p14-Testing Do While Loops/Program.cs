/*
Random random = new Random();
int current = random.Next(1, 11);


do
{
	current = random.Next(1, 11);

	if (current >= 8) continue;

	Console.WriteLine(current);
} while (current != 7);
*/

/*
while (current >= 3)
{
	Console.WriteLine(current);
	current = random.Next(1, 11);
}
Console.WriteLine($"Last number: {current}");
*/
/*
Random attack = new();
int currentHit = attack.Next(1, 11);
string player = "Hero";
string monster = "Monster";

int playerHP = 10;
int mobHP = 10;

do
{
	currentHit = attack.Next(1, 11);
	mobHP -= currentHit;
	Console.WriteLine($"{monster} was damaged and lost {currentHit} health and now has {mobHP} health.");
	if (mobHP <= 0)
		break;

	currentHit = attack.Next(1, 11);
	playerHP -= currentHit;
	Console.WriteLine($"{player} was damaged and lost {currentHit} health and now has {playerHP} health.");
	if (playerHP <= 0)
		break;

} while ((mobHP >= 0) || (playerHP >= 0));

Console.WriteLine( playerHP > mobHP ? "Hero wins!" : "Monster wins!");

if (playerHP > 0)
	Console.WriteLine($"{player} wins!");
else if (mobHP > 0)
	Console.WriteLine($"{monster} wins!");
*/

string? readResult;
bool validEntry = false;
Console.WriteLine("Enter a string containing at least three characters");
do
{
	readResult = Console.ReadLine();
	if (readResult != null)
	{
		if (readResult.Length >= 3)
		{
			validEntry = true;
		}
		else
		{
			Console.WriteLine("Your inut is invalid, please try again");
		}
	}
} while (validEntry == false);
Console.WriteLine($"Your entered value was {readResult}");