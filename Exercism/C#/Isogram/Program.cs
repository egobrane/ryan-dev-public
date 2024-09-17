using System;
using System.Collections.Generic;

namespace Isogram;

public static class Isogram
{
    public static void Main(string[] args)
    {
        IsIsogram("subdermatoglyphic");
    }
    public static bool IsIsogram(string word)
    {
        HashSet<char> chars = new HashSet<char>();
        foreach (char c in word)
        {
            char cLower = Char.ToLower(c);
            if (cLower < 'a' || c > 'z')
            {
                continue;
            }
            if (chars.Contains(cLower))
            {
                return false;
            }
            chars.Add(cLower);
        }
        return true;
    }
}
