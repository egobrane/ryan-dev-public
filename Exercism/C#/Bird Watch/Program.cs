using System;
using System.Linq;

class BirdCount
{
    private int[] birdsPerDay;

    public static void Main(string[] args)
    {
        BirdCount.LastWeek();
        // => [0, 2, 5, 3, 7, 8, 4]
        int[] birdsPerDay = { 2, 5, 0, 7, 4, 1 };
        var birdCount = new BirdCount(birdsPerDay);
        birdCount.Today();
        // => 1
        birdCount.IncrementTodaysCount();
        birdCount.Today();
        // => 2
        birdCount.HasDayWithoutBirds();
        // => true, because day 3 had no birds
        birdCount.CountForFirstDays(4);
        // => 14, because 2 + 5 + 0 + 7 = 14
        birdCount.BusyDays();
        // => 2, because two days had five or more birds
    }

    public BirdCount(int[] birdsPerDay)
    {
        this.birdsPerDay = birdsPerDay;
    }

    public static int[] LastWeek()
    {
        int[] sightings = { 0, 2, 5, 3, 7, 8, 4 };
        return sightings;
    }

    public int Today()
    {
        if (birdsPerDay.Length > 0)
        {
            int todayCount = birdsPerDay[birdsPerDay.Length - 1];
            return todayCount;
        }
        return 0;
    }

    public void IncrementTodaysCount()
    {
        if (birdsPerDay.Length > 0)
        {
            birdsPerDay[birdsPerDay.Length -1] += 1;
        }
    }

    public bool HasDayWithoutBirds()
    {
        foreach (int day in birdsPerDay)
        {
            if (day == 0)
            {
                return true;
            }
        }
        return false;
    }

    public int CountForFirstDays(int numberOfDays)
    {
        int count = 0;
        for (int i = 0; i < numberOfDays; i++)
        {
            count += birdsPerDay[i];
        }
        return count;
    }

    public int BusyDays()
    {
        int busyDays = 0;
        foreach (int day in birdsPerDay)
        {
            if (day >= 5)
            {
                busyDays += 1;
            }
        }
        return busyDays;
    }

    /*
    public int Today()
    {
        for (int i = 0; i <= birdsPerDay.Length; i++)
        {
            int currentDay = birdsPerDay[i];
            if (i == birdsPerDay.Length -1)
            {
                Console.WriteLine(currentDay);
                return currentDay;
            }
        }
        return 0;
    }
*/
}
