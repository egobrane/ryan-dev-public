namespace Pangram;

public static class Pangram
{
    public static void Main(string[] args)
    {
        Pangram.IsPangram("The quick brown fox jumps over the lazy");
    }
    public static bool IsPangram(string input)
    {
        bool IsPangram = true;
        string alphabet = "abcdefghijklmnopqrstuvwxyz";
        char[] alphabetArray = alphabet.ToCharArray();
        foreach (char c in alphabetArray)
        {
            if (!input.ToLower().Contains(c))
            {
                IsPangram = false;
            }
        }
        Console.WriteLine(IsPangram);
        return IsPangram;
    }
}
