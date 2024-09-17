namespace Tim_from_Marketing;

class Badge
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
        Badge.Print(734, "Ernest Johnny Payne", "Strategic Communication");
        // => "[724] - Ernest Johnny Payne - STRATEGIC COMMUNICATION"
        Badge.Print(id: null, "Jane Johnson", "Procurement");
        // => "Jane Johnson - PROCUREMENT"
        Badge.Print(id: null, "Charlotte Hale", department: null);
        // => "Charlotte Hale - OWNER"
    }

    public static string Print(int? id, string name, string? department)
    {
        string idNumber = id.HasValue ? $"[{id.Value.ToString()}] - " : "";
        return $"{idNumber}{name} - {department?.ToUpper() ?? "OWNER"}";
    }

    // Expression-Bodied Method:
    // public static string Print(int? id, string name, string? department) => $"{(id == null ? "" : $"[{id}] - ")}{name} - {department?.ToUpper() ?? "OWNER"}";
}
