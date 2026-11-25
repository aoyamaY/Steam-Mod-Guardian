using Microsoft.Win32;
using Guardian.Core;
using System.IO;
using System.Text.RegularExpressions;
namespace Guardian.App;
internal static class SteamPaths
{
    public static List<SteamGame> Detect()
    {
        var steam=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string? p) { if(!string.IsNullOrWhiteSpace(p)) steam.Add(p.Replace('/','\\')); }
        try { Add(Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam","SteamPath",null) as string); } catch { }
        try { Add(Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam","InstallPath",null) as string); } catch { }
        Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),"Steam"));
        var libs=new HashSet<string>(steam,StringComparer.OrdinalIgnoreCase);
        foreach(var s in steam)
        {
            var path=Path.Combine(s,"steamapps","libraryfolders.vdf");
            if(!File.Exists(path))continue;
            var vdf=File.ReadAllText(path);
            foreach(Match m in Regex.Matches(vdf,"\"path\"\\s*\"((?:\\\\.|[^\"\\\\])*)\"",RegexOptions.IgnoreCase))libs.Add(m.Groups[1].Value.Replace("\\\\","\\"));
        }
        return SteamCatalog.Discover(libs);
    }
}
