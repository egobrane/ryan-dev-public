using System;
using System.Collections.Generic;

namespace Accumulate;

public static class AccumulateExtensions
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
    }

    public static IEnumerable<U> Accumulate<T, U>(this IEnumerable<T> collection, Func<T, U> func)
    {
        throw new NotImplementedException("You need to implement this method.");
    }
}
