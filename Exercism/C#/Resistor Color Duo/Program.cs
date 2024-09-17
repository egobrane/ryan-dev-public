using System;
using System.Collections.Generic;

namespace Resistor_Color_Duo;

public static class ResistorColorDuo
{
    public static readonly Dictionary <string, int> colorTable = new Dictionary<string, int>
    {
        { "black", 0 },
        { "brown", 1 },
        { "red", 2 },
        { "orange", 3 },
        { "yellow", 4 },
        { "green", 5 },
        { "blue", 6 },
        { "violet", 7 },
        { "grey", 8 },
        { "white", 9 }
    };

    static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
    }
    public static int Value(string[] colors)
    {
        string returnString = "";
        for (int i = 0; i < 2; i++)
        {
            returnString += colorTable[colors[i]];
        }
        return int.Parse(returnString);
    }
    public static int ColorCode(string color) => colorTable[color];

    public static string[] Colors() => new string[] { "black", "brown", "red", "orange", "yellow", "green", "blue", "violet", "grey", "white" };

}
