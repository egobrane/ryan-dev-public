using System;
using System.Collections.Generic;
namespace Robot_Name;

class Robot
{
    private string? name;
    private static Random robotName = new Random();
    private static List<string> robotNames = new List<string>();
    public static void Main(string[] args)
    {
        var robot = new Robot();
        Console.WriteLine(robot.Name);
        robot.Reset();
        Console.WriteLine(robot.Name);
    }
    public string Name
    {
        get
        {
            if (name == null)
            {
                Reset();
            }
            return name;
        }
    }

    public void Reset()
    {
        char firstLetter = (char)robotName.Next(65, 91);
        char secondLetter = (char)robotName.Next(65, 91);
        int digits = robotName.Next(100, 1000);
        if (robotNames.Contains($"{firstLetter}{secondLetter}{digits}"))
        {
            Reset();
        }
        else
        {
            name = $"{firstLetter}{secondLetter}{digits}";
            robotNames.Add(name);
        }
    }
}
