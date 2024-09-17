using System.Linq;

public static class Bob
{
    public static void Main()
    {
        string test = "f5!!!";
        if (test.Any(char.IsLetter))
        {
            Console.WriteLine(test);
        }
    }
    public static string Response(string statement)
    {
        if (statement.Trim() == "")
        {
            return "Fine. Be that way!";
        }
        else if ((statement.ToUpper() == statement) && statement.EndsWith("?") && statement.Any(char.IsLetter))
        {
            return "Calm down, I know what I'm doing!";
        }
        else if ((statement.ToUpper() == statement) && statement.Any(char.IsLetter))
        {
            return "Whoa, chill out!";
        }
        else if (statement.Trim().EndsWith("?"))
        {
            return "Sure.";
        }
        else
        {
            return "Whatever.";
        }
    }
}