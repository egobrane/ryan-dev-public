namespace Need_for_Speed;

class Program
{
    static void Main()
    {
        int speed = 9;
        int batteryDrain = 50;
        var car = new RemoteControlCar(speed, batteryDrain);
        var fastCar = RemoteControlCar.Nitro();


        int distance = 100;
        var RaceTrack = new RaceTrack(distance);

        car.Drive();

        car.DistanceDriven();
        // => 5
        car.BatteryDrained();
        // => false

        RaceTrack.TryFinishTrack(car);

        fastCar.Drive();
        fastCar.Drive();
        fastCar.DistanceDriven();
        fastCar.BatteryDrained();

        RaceTrack.TryFinishTrack(fastCar);
    }
}

class RemoteControlCar
{
    // TODO: define the constructor for the 'RemoteControlCar' class

    public int speed;
    public int batteryDrain;
    public int distanceDriven;
    public int batteryLevel = 100;

    public RemoteControlCar(int speed, int batteryDrain)
    {
        this.speed = speed;
        this.batteryDrain = batteryDrain;
    }

    public bool BatteryDrained() => batteryLevel < batteryDrain;

    public int DistanceDriven() => distanceDriven;

    public object? Drive() => batteryLevel >= batteryDrain ? (distanceDriven += speed, batteryLevel -= batteryDrain) : null;

    public static RemoteControlCar Nitro() => new RemoteControlCar(50, 4);
}

class RaceTrack
{
    public int distance;
    public RaceTrack(int distance)
    {
        this.distance = distance; 
    }
    public bool TryFinishTrack(RemoteControlCar car) => (car.speed * (car.batteryLevel / car.batteryDrain) >= distance);

}