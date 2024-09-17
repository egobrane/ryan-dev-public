class Lasagna
{
    static void Main() {
        var lasagna = new Lasagna();
        lasagna.RemainingMinutesInOven(30);
        lasagna.ElapsedTimeInMinutes(2, 20);
        lasagna.PreparationTimeInMinutes(2);
        Console.WriteLine("Test");
    }
    public int ExpectedMinutesInOven()
    {
        return 40;
    }

    public int RemainingMinutesInOven(int minutes)
    {
        return ExpectedMinutesInOven() - minutes;
    }

    public int PreparationTimeInMinutes(int layers)
    {
        return layers * 2;
    }

    public int ElapsedTimeInMinutes(int layers, int minutes)
    {
        return PreparationTimeInMinutes(layers) + minutes;
    }
}
