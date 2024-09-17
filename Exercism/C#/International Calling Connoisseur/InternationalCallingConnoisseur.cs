using System;
using System.Collections.Generic;

public static class DialingCodes
{
    public static void Main(string[] args)
    {
        DialingCodes.GetEmptyDictionary();
        // => empty dictionary
        DialingCodes.GetExistingDictionary();
        // => 1 => "United States of America", 55 => "Brazil", 91 => "India
        DialingCodes.AddCountryToEmptyDictionary(44, "United Kingdom");
        // => 44 => "United Kingdom"
        DialingCodes.AddCountryToExistingDictionary(DialingCodes.GetExistingDictionary(), 44, "United Kingdom");
        // => 1 => "United States of America", 44 => "United Kingdom", 55 => "Brazil", 91 => "India"
        DialingCodes.GetCountryNameFromDictionary(DialingCodes.GetExistingDictionary(), 55);
        // => "Brazil"
        DialingCodes.GetCountryNameFromDictionary(DialingCodes.GetExistingDictionary(), 999);
        // => string.Empty
        DialingCodes.CheckCodeExists(DialingCodes.GetExistingDictionary(), 55);
        // => true
        DialingCodes.UpdateDictionary(DialingCodes.GetExistingDictionary(), 1, "Les Etats-Unis");
        // => 1 => "Les Etats-Unis", 55 => "Brazil", 91 => "India"
        DialingCodes.UpdateDictionary(DialingCodes.GetExistingDictionary(), 999, "Newlands");
        // => 1 => "United States of America", 55 => "Brazil", 91 => "India"
        DialingCodes.RemoveCountryFromDictionary(DialingCodes.GetExistingDictionary(), 91);
        // => 1 => "United States of America", 55 => "Brazil"
        DialingCodes.FindLongestCountryName(DialingCodes.GetExistingDictionary());
        // => "United States of America"
    }
    public static Dictionary<int, string> GetEmptyDictionary()
    {
        var emptyDictionary = new Dictionary<int, string>();
        return emptyDictionary;
    }

    public static Dictionary<int, string> GetExistingDictionary()
    {
        var existingDictionary = new Dictionary<int, string>
        {
            { 1, "United States of America" },
            { 55, "Brazil" },
            { 91, "India" }
        };
        return existingDictionary;
    }

    public static Dictionary<int, string> AddCountryToEmptyDictionary(int countryCode, string countryName)
    {
        var newDictionary = GetEmptyDictionary();
        newDictionary.Add(countryCode, countryName);
        return newDictionary;
    }

    public static Dictionary<int, string> AddCountryToExistingDictionary(
        Dictionary<int, string> existingDictionary, int countryCode, string countryName)
    {
        existingDictionary.Add(countryCode, countryName);
        return existingDictionary;
    }

    public static string GetCountryNameFromDictionary(
        Dictionary<int, string> existingDictionary, int countryCode)
    {
        if (existingDictionary.ContainsKey(countryCode))
        {
            return existingDictionary[countryCode];
        }
        return string.Empty;
    }

    public static bool CheckCodeExists(Dictionary<int, string> existingDictionary, int countryCode)
    {
        return existingDictionary.ContainsKey(countryCode);
    }

    public static Dictionary<int, string> UpdateDictionary(
        Dictionary<int, string> existingDictionary, int countryCode, string countryName)
    {
        if (existingDictionary.ContainsKey(countryCode))
        {
            existingDictionary[countryCode] = countryName;
        }
        return existingDictionary;
    }

    public static Dictionary<int, string> RemoveCountryFromDictionary(
        Dictionary<int, string> existingDictionary, int countryCode)
    {
        if (existingDictionary.ContainsKey(countryCode))
        {
            existingDictionary.Remove(countryCode);
        }
        return existingDictionary;
    }

    public static string FindLongestCountryName(Dictionary<int, string> existingDictionary)
    {
        throw new NotImplementedException($"Please implement the (static) FindLongestCountryName() method");
    }
}