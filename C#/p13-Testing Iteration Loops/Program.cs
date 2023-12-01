/*
string[] names = { "Alex", "Eddie", "David", "Michael" };

// backwards
for (int i = names.Length -1; i >= 0; i--)
{
	Console.WriteLine(names[i]);
}


// forwards
for (int i = 0; i < names.Length; i++)
{
	if (names[i] == "David") names[i] = "Sammy";
}
foreach (var name in names) 
{
	Console.WriteLine(name);
}
*/
Console.WriteLine("Enter the maximum integer to FizzBuzz!");
int maximum = Convert.ToInt32(Console.ReadLine());
for (int i = 1; i <= maximum; i++)
{
	string determination = "";
	if ((i % 3 == 0) && (i % 5 == 0))
	{
		determination = "FizzBuzz";
	}
	else if (i % 3 == 0)
	{
		determination = "Fizz";
	}
	else if (i % 5 == 0)
	{
		determination = "Buzz";
	}
	if (determination != "")
	{
		Console.WriteLine($"{i} - {determination}");
	}
	else
	{
		Console.WriteLine(i);
	}
}