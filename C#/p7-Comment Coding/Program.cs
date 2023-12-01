/* 
	This code takes a string, turns the letters into an array,
	reverses the array, and then counts the o's.
*/

string originalMessage = "The quick brown fox jumps over the lazy dog.";

char[] charMessage = originalMessage.ToCharArray();
Array.Reverse(charMessage);

int oCount = 0;

foreach (char character in charMessage) 
{ 
	if (character == 'o') 
	{ 
		oCount++;
	} 
}
string newMessage = new String(charMessage);

Console.WriteLine(newMessage);
Console.WriteLine($"'o' appears {oCount} times.");