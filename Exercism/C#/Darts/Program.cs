namespace Darts;

public static class Darts
{
    static void Main(string[] args)
    {
        Darts.Score(0, 10);
    }

    public static int Score(double x, double y)
    {
        double distance = Math.Sqrt(x * x + y * y);
        Console.WriteLine(distance);
        switch (distance)
        {
            case <= 1.0:
                return 10;
            case <= 5.0:
                return 5;
            case <= 10.0:
                return 1;
            default:
                return 0;
        }
    }
}
