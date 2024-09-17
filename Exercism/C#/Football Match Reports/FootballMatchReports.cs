namespace Football_Match_Reports;
{
    using OffFieldActivitiesAndCharacters;
    public static class PlayAnalyzer
    {
        public static void Main(string[] args)
        {
        }
        public static string AnalyzeOnField(int shirtNum)
        {
            return shirtNum switch
            {
                1 => "goalie",
                2 => "left back",
                3 or 4 => "center back",
                5 => "right back",
                6 or 7 or 8 => "midfielder",
                9 => "left wing",
                10 => "striker",
                11 => "right wing",
                _ => throw new ArgumentOutOfRangeException(nameof(shirtNum)),
            };
        }

        public static string AnalyzeOffField(object report)
        {
            Console.WriteLine($"Type of report: {report.GetType()}");
            return report switch
            {
                int count => $"There are {count} supporters at the match.",
                string message => message,
                Foul foul => foul.GetDescription(),
                Injury injury => $"Oh no! {injury.GetDescription()} Medics are on the field.",
                Incident incident => incident.GetDescription(),
                Manager manager when manager.Club == null => manager.Name,
                Manager manager => $"{manager.Name} ({manager.Club})",
                _ => throw new ArgumentException("Invalid report type")
            };
            
        }
    }
}