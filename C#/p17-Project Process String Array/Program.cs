string[] myStrings = new string[2] { "I like pizza. I like roast chicken. I like salad", "I like all three of the menu choices" };
string myString = "";

int stringsCount = myStrings.Length;
int periodLocation = 0;

for (int i = 0; i < stringsCount; i++)
{
	myString = myStrings[i];
	periodLocation = myString.IndexOf(".");

	string mySentence;

	// extract sentences from each string and display them one at a time
	while (periodLocation != -1)
	{

		// first sentence is the string value to the left of the period location
		mySentence = myString.Remove(periodLocation);

		// the remainder of myString is the string value to the right of the location
		myString = myString.Substring(periodLocation + 1);

		// remove any leading white-space from myString
		myString = myString.TrimStart();

		// update the comma location and increment the counter
		periodLocation = myString.IndexOf(".");

		Console.WriteLine(mySentence);
	}

	mySentence = myString.Trim();
	Console.WriteLine(mySentence);
}