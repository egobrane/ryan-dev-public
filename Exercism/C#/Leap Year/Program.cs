using System;

namespace Leap_Year;


public static class Leap
{
    static void Main()
    {
        IsLeapYear(420);

    }
    public static bool IsLeapYear(int year)
    {
        if (year % 4 == 0)
        {
            if (year % 100 == 0)
            {
                if (year % 400 == 0)
                {
                    return true;
                }
                return false;
            }
            return true;
        }
        return false;
    }

    public static bool IsLeapYearTwo(int year)
    {
        if ((year % 4 == 0 && year % 100 == 0 && year % 400 == 0) || (year % 4 == 0 &&  year % 100 != 0))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    public static bool IsLeapYearThree(int year)
    {
        return (year % 4 == 0 && (year % 100 !=0 || year % 400 == 0));
    }
}