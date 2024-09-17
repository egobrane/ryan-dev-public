using System;

static class LogLine
{ 
    public static void Main()
    {
        LogLine.Message("[ERROR]: Invalid operation");
        // => "Invalid operation"
        LogLine.LogLevel("[ERROR]: Invalid operation");
        // => "error"
        LogLine.Reformat("[INFO]: Operation completed");
        // => "Operation completed (info)"
    }
    public static string Message(string logLine)
    {
        int openingPosition = logLine.LastIndexOf(':');
        return logLine.Substring(openingPosition + 2).Trim();
        // could also do return logLine.Substring(logLine.IndexOf(":") +1).Trim();
    }

    public static string LogLevel(string logLine)
    {
        int closingPosition = logLine.LastIndexOf(':');
        return logLine.Substring(0, closingPosition).Trim('[', ']').ToLower();
        // could also do return logLine.Substring(1, logLine.IndexOf("]") -1).ToLower();
    }

    public static string Reformat(string logLine)
    {
        return $"{Message(logLine)} ({LogLevel(logLine)})";
    }
}
