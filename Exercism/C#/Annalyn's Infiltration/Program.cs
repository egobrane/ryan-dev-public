using System;

static class QuestLogic
{
    public static void Main()
    {
        Console.WriteLine("program");
        bool knightIsAwake = true;
        bool archerIsAwake = false;
        bool prisonerIsAwake = true;
        bool petDogIsPresent = false;
        QuestLogic.CanFastAttack(true);
        string output = knightIsAwake.ToString();
        Console.WriteLine(output);
    }
    public static bool CanFastAttack(bool knightIsAwake)
    {
        return !knightIsAwake;
    }

    public static bool CanSpy(bool knightIsAwake, bool archerIsAwake, bool prisonerIsAwake)
    {
        return knightIsAwake || archerIsAwake || prisonerIsAwake;
    }

    public static bool CanSignalPrisoner(bool archerIsAwake, bool prisonerIsAwake)
    {
        return prisonerIsAwake && !archerIsAwake;
    }

    public static bool CanFreePrisoner(bool knightIsAwake, bool archerIsAwake, bool prisonerIsAwake, bool petDogIsPresent)
    {
        return (petDogIsPresent && !archerIsAwake) || (prisonerIsAwake && !knightIsAwake && !archerIsAwake);
        
    }
}
