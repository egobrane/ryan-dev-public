using System;
namespace Difference_of_Squares;

class DifferenceOfSquares
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
        CalculateSquareOfSum(7);
        CalculateSumOfSquares(7);
    }

    public static int CalculateSquareOfSum(int max)
    {
        int[] intArray = new int[max];
        int sum = 0;
        for (int i = 0; i < max; i++)
        {
            intArray[i] = i + 1;
        }
        foreach (int i in intArray)
        {
            sum += i;
        }
        return sum * sum;
    }

    /*
    alternative:
    public static int CalculateSquareOfSum(int max)
    {
        int sum = 0;
        for (int i = 1; i <= max; i++)
        {
            total += i;
        }
        return sum * sum;
    }
    */

    public static int CalculateSumOfSquares(int max)
    {
        int[] intArray = new int[max];
        int sumSquare = 0;
        for (int i = 0; i < max; i++)
        {
            intArray[i] = i + 1;
        }
        foreach (int i in intArray)
        {
            sumSquare += i * i;
        }
        return sumSquare;
    }

    /*
    alternative:
    public static int CalculateSumOfSquares(int max)
    {
        int sum = 0;
        for (int i = 1; i <= max; i++)
        {
            total += i*i;
        }
        return total;
    }
    */

    public static int CalculateDifferenceOfSquares(int max) => DifferenceOfSquares.CalculateSquareOfSum(max) - DifferenceOfSquares.CalculateSumOfSquares(max);
}
