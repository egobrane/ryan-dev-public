using System;
using System.Linq;

namespace Binary_Search;

public static class BinarySearch
{
    public static void Main()
    {   var array = new[] { 1, 3, 4, 6, 8, 9, 11 };
        var blankArray = Array.Empty<int>();
        BinarySearch.FindNew(array, 11);
        BinarySearch.FindNew(blankArray, 1);
    }
    public static int FindNew(int[] input, int value)
    {
        if (input.Length > 0)
        {
            Array.Sort(input);
            int left = 0;
            int right = input.Length - 1;

            while (left <= right)
            {
                int middle = (left + right) / 2;
                if (input[middle] == value)
                {
                    return middle;
                }
                else if (input[middle] < value)
                {
                    left = middle + 1;
                }
                else
                {
                    right = middle - 1;
                }
            }
        }
        return -1;
    }

    public static int Find(int[] input, int value)
    {
        Array.Sort(input);
        int divider = input.Length / 2;
        if (value > input[divider])
        {
            int[] result = input.Skip(divider).ToArray();
        }
        if (value < input[divider])
        {
            int[] result = input.Take(divider).ToArray();
        }
        if (value == input[divider])
        {
            return input[divider];
        }
        return input[divider];
    }
}
