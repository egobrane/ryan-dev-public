using System;

static class AssemblyLine
{
    public static void Main()
    {
        AssemblyLine.SuccessRate(10);
        AssemblyLine.ProductionRatePerHour(6);
        AssemblyLine.WorkingItemsPerMinute(6);
    }
    public static double SuccessRate(int speed)
    {
        if (speed == 10)
        {
            return 0.77;
        }
        else if (speed > 8 && speed < 10)
        {
            return 0.80;
        }
        else if (speed >= 5 && speed <= 8)
        {
            return 0.90;
        }
        else if (speed >= 1 && speed <= 4)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    
    public static double ProductionRatePerHour(int speed)
    {
        // my method
        //double success = AssemblyLine.SuccessRate(speed);
        //return (speed * 221) * success;
        return speed * 211 * SuccessRate(speed);
    }

    public static int WorkingItemsPerMinute(int speed)
    {
        // my method
        //int perMinute = (int)AssemblyLine.ProductionRatePerHour(speed);
        //return perMinute / 60;
        return (int)ProductionRatePerHour(speed) / 60;
    }
}
