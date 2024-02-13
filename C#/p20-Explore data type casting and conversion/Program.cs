/* widening conversion, implicit
int myInt = 3;
Console.WriteLine($"int: {myInt}");

decimal myDecimal = myInt;
Console.WriteLine($"decimal: {myDecimal}");
*/

/* narrowing conversion, explicit
decimal myDecimal = 3.14m;
Console.WriteLine($"decimal: {myDecimal}");

int myInt = (int)myDecimal;
Console.WriteLine($"int: {myInt}");
*/
/* convert integers to string (all types can be converted to string)
int first = 5;
int second = 7;
string message = first.ToString() + second.ToString();
Console.WriteLine(message);
*/

/* parse method
string first = "5";
string second = "7";
int sum = int.Parse(first) + int.Parse(second);
Console.WriteLine(sum);
*/

/* convert method
string value1 = "5";
string value2 = "7";
int result = Convert.ToInt32(value1) * Convert.ToInt32(value2);
Console.WriteLine(result);
*/

/*
int value = (int)1.5m; // casting truncates
Console.WriteLine(value);

int value2 = Convert.ToInt32(1.5m); // converting rounds up
Console.WriteLine(value2);
*/
/*
string value3 = "1bad";
int result = 0;
if (int.TryParse(value3, out result))
{
	Console.WriteLine($"Measurement: {result}");
}
else
{
	Console.WriteLine("Unable to report the measurement.");
}
if (result > 0)
	Console.WriteLine($"Measurement (w/ offset): {50 + result}");

*/
/*
string[] values = { "12.3", "45", "ABC", "11", "DEF" };
decimal total = 0m;
string combinedString = "";
foreach (string value in values)
{
	decimal add = 0m;
	if (decimal.TryParse(value, out add))
	{
		total += add;
		Console.WriteLine($"Adding {add} to {total}");
	}
	else
	{
		combinedString += value.ToString();
	}
}
Console.WriteLine($"Message: {combinedString}");
Console.WriteLine($"Total: {total}");
*/
int value1 = 12;
decimal value2 = 6.2m;
float value3 = 4.3f;

// Your code here to set result 1
// could also use int result1 = Convert.ToInt32((decimal)value1 / value2);
int result1 = Convert.ToInt32(value1) / Convert.ToInt32(value2);
Console.WriteLine($"Divide value1 by value2, display the result as an int: {result1}");

// Your code here to set result 2
decimal result2 = value2 / (decimal)value3;
Console.WriteLine($"Divide value2 by value3, display the result as decimal: {result2}");

// Your code here to set result 3
float result3 = value3 / (float)value1;
Console.WriteLine($"Divide value3 by value1, display the result as a float: {result3}");