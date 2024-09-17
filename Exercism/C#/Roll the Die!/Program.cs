using System;
namespace Roll_the_Die_;

public class Player
{
    static void Main(string[] args)
    {
        var player = new Player();
        player.RollDie();
        // => >= 1 <= 18
        player.GenerateSpellStrength();
        // => >= 0.0 < 100.0
    }

    public int RollDie()
    {
        Random dice = new Random();
        Console.WriteLine(dice.Next(1, 19));
        return dice.Next(1, 19);
    }

    public double GenerateSpellStrength()
    {
        Random strength = new Random();
        Console.WriteLine((double)strength.Next(0, 100));
        return (double)strength.Next(0, 100);
    }
}