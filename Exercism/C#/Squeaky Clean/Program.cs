using System.Text;
using System.Text.RegularExpressions;

namespace Squeaky_Clean;

public static class Identifier
{
    public static void Main()
    {
        Identifier.Clean("my   Id");
        // => "my___Id"
        Identifier.Clean("my\0Id");
        Identifier.Clean("1😀2😀3😀");
        // => ""
    }
    public static string Clean(string identifier)
    {
        StringBuilder result = new StringBuilder();
        bool capitalizeNext = false;

        foreach (char c in identifier)
        {
            if (c >= 'α' && c <= 'ω')
            {
                continue;
            }
            if (char.IsControl(c))
            {
                result.Append("CTRL");
            }
            else if (c == ' ')
            {
                result.Append("_");
            }
            else if (c == '-')
            {
                capitalizeNext = true;
            }
            else
            {
                if (capitalizeNext)
                {
                    result.Append(char.ToUpper(c));
                    capitalizeNext = false;
                }
                else
                {
                    if (Char.IsLetter(c))
                    {
                        result.Append(c);
                    }
                }
            }
        }
        Console.WriteLine(result.ToString());
        return result.ToString();
    }
}
