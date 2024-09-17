using System;
using System.Collections.Generic;
using System.Linq;

public static class Languages
{

    static void Main()
    {
        Languages.NewList();
        // => empty list
        Languages.GetExistingLanguages();
        // => {"C#", "Clojure", "Elm"}
        Languages.AddLanguage(Languages.GetExistingLanguages(), "VBA");
        // => {"C#", "Clojure", "Elm", "VBA"}
        Languages.CountLanguages(Languages.GetExistingLanguages());
        // => 3
        Languages.HasLanguage(Languages.GetExistingLanguages(), "Elm");
        // => true
        Languages.ReverseList(Languages.GetExistingLanguages());
        // => {"Elm", "Clojure", "C#" }
        Languages.IsExciting(Languages.GetExistingLanguages());
        // => true
        Languages.RemoveLanguage(Languages.GetExistingLanguages(), "Clojure");
        // => {"C#", "Elm" }
        Languages.IsUnique(Languages.GetExistingLanguages());
        // => true
    }
    public static List<string> NewList() => new List<string>();

    public static List<string> GetExistingLanguages() => new List<string>{ "C#", "Clojure", "Elm" };

    public static List<string> AddLanguage(List<string> languages, string language) => languages.Append(language).ToList();

    public static int CountLanguages(List<string> languages) => languages.Count;

    public static bool HasLanguage(List<string> languages, string language) => languages.Contains(language);

    public static List<string> ReverseList(List<string> languages) => languages.Select(x => x).Reverse().ToList();

    public static bool IsExciting(List<string> languages) => (languages == null || languages.Count == 0) ? false : languages[0].Equals("C#") || (languages[1].Equals("C#") && (languages.Count == 2 || languages.Count == 3));

    public static List<string> RemoveLanguage(List<string> languages, string language) => languages.Where(l => l != language).ToList();

    public static bool IsUnique(List<string> languages) => languages.Distinct().Count() == languages.Count();
}
