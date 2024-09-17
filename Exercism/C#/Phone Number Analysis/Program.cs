using System;
namespace Phone_Number_Analysis;


public static class PhoneNumber
{
    static void Main(string[] args)
    {
        PhoneNumber.Analyze("631-555-1234");
        // should return (false, true, "1234")
        PhoneNumber.IsFake(PhoneNumber.Analyze("631-555-1234"));
        // should return true
    }
    public static (bool IsNewYork, bool IsFake, string LocalNumber) Analyze(string phoneNumber)
    {
        string[] numbers = phoneNumber.Split('-');
        bool IsNewYork = false;
        bool IsFake = false;
        string LocalNumber = numbers[2];
        if (int.TryParse(numbers[0], out int areaCode) && areaCode == 212 )
        {
            IsNewYork = true;
        }
        if (int.TryParse(numbers[1], out int regionCode) && regionCode == 555)
        {
            IsFake = true;
        }
        return (IsNewYork, IsFake, LocalNumber);
        /* alternative:
        string[] numbers = phoneNumber.Split('-');
        return (numbers[0] == "212", numbers[1] == "555", numbers[2]);
        */
    }

    public static bool IsFake((bool IsNewYork, bool IsFake, string LocalNumber) phoneNumberInfo)
    {
        return phoneNumberInfo.IsFake;
    }

    // other way to do a direct return: "expression-bodied method"
    // public static bool IsFake((bool IsNewYork, bool Is Fake, string LocalNumber) phoneNumberInfo) => phoneNumberInfo.IsFake;
}
