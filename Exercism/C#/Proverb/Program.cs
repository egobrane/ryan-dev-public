namespace Proverb;

public static class Proverb
{
    static void Main(string[] args)
    {
        Proverb.Recite(new [] {"nail", "shoe", "horse", "rider"});
    }
    public static string[] Recite(string[] subjects)
    {
        if (subjects.Length == 0)
        {
            return Array.Empty<string>();
        }
        string[] proverb = new string[subjects.Length];
        int j = 0;
        for (int i = 0; i < subjects.Length -1; i++)
        {
            proverb[j] = $"For want of a {subjects[i]} the {subjects[i+1]} was lost.";
            j++;
        }
        proverb[j] = $"And all for the want of a {subjects[0]}.";
        return proverb;
    }
}
