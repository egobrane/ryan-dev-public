using System;

namespace Elon_s_Toys;

class RemoteControlCar
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
        var car = RemoteControlCar.Buy();
        car.DistanceDisplay();
        // => "Driven 0 meters"
        car.BatteryDisplay();
        // => "Battery at 100%"
        car.Drive();
        car.Drive();
        car.DistanceDisplay();
        // => "Driven 40 meters"
        car.BatteryDisplay();
        car.Drive();
        car.Drive();
        car.Drive();
        car.DistanceDisplay();
        car.BatteryDisplay();
        // => "Battery at 98%"
    }

    public int distance = 0;

    public decimal battery = 1.00m;

    public static RemoteControlCar Buy() => new RemoteControlCar();

    public string DistanceDisplay() => $"Driven {distance} meters";

    public string BatteryDisplay() =>
        battery > 0.00m ? $"Battery at {battery.ToString("P0").Replace(" ", "")}" : "Battery empty";

    public void Drive()
    {
        if (battery != 0.00m)
        {
            distance += 20;
            battery -= 0.01m;
        }
    }
}
