using System.Linq;

namespace Reverse_String;

class Program
{
    static void Main(string[] args)
    {
        Reverse("sports");
    }

    public static string Reverse(string input)
    {
        char[] inputArray = input.ToCharArray();
        char[] reversed = new char[inputArray.Length];
        for (int i = 0; i < inputArray.Length; i++)
        {
            reversed[inputArray.Length -i -1] = inputArray[i];
        }
        string returnString = new string(reversed);
        Console.WriteLine($"{reversed}");
        return returnString;
    }

    public static string ReverseLinq(string input) => new string(input.Reverse().ToArray());
}
