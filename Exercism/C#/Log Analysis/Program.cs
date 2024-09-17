using System;

public static class LogAnalysis 
{
    public static void Main()
    {
        string log = "FIND >>> SOMETHING <===< HERE";
        log.SubstringAfter(": "); // => returns "File Deleted."
        //log.SubstringBetween("[", "]"); // => returns "INFO".
        log.Message(); // => returns "File Deleted."
        log.LogLevel(); // => returns "INFO".
        Console.WriteLine(log.SubstringBetween(">>> ", " <===<"));
    }
    public static string SubstringAfter(this string log, string delimiter) => log.Substring(log.IndexOf(delimiter) + delimiter.Length);

    public static string SubstringBetween(this string log, string openBracket, string closeBracket)
    {
        int open = log.IndexOf(openBracket) + openBracket.Length;
        int close = log.LastIndexOf(closeBracket);
        return log.Substring(open, close - open).Trim();
        // could also be done with split alone: return log.Split(openBracket)[1].Split(closeBracket)[0];
    }
    public static string Message(this string log)
    {
        return log.SubstringAfter(": ");
    }

    public static string LogLevel(this string log)
    {
        return log.SubstringBetween("[", "]");
    }
}