using System.Text.RegularExpressions;
namespace Guardian.Core;
public sealed record SteamGame(string AppId,string Name,List<string> Roots,bool Installed,string AltName="",string LocalizedName="")
{
    public string DisplayName => string.IsNullOrWhiteSpace(LocalizedName) || string.Equals(Name,LocalizedName,StringComparison.OrdinalIgnoreCase) ? Name : $"{LocalizedName} / {Name}";
    public string Label => $"{DisplayName}  [{AppId}]  ·  {(Installed?"已安装":"仅工坊内容")}  ·  {Roots.Count} 个目录";
}
public static class SteamCatalog
{
    private static string Value(string text,string key)
    {
        var m=Regex.Match(text,"\""+Regex.Escape(key)+"\"\\s*\"((?:\\\\.|[^\"\\\\])*)\"",RegexOptions.IgnoreCase);
        return m.Success?m.Groups[1].Value.Replace("\\\\","\\").Replace("\\\"","\""):"";
    }
    public static bool Id(string? s)=>s is {Length:>0} && s.All(c=>c>='0'&&c<='9') && uint.TryParse(s,out var n)&&n>0;
    public static (string AppId,string WorkshopId) WorkshopIdentity(string path)
    {
        var parts=path.Split(['\\','/'],StringSplitOptions.RemoveEmptyEntries);
        for(int i=0;i+3<parts.Length;i++)if(parts[i].Equals("workshop",StringComparison.OrdinalIgnoreCase)&&parts[i+1].Equals("content",StringComparison.OrdinalIgnoreCase)&&Id(parts[i+2])&&ulong.TryParse(parts[i+3],out var item)&&item>0)return(parts[i+2],parts[i+3]);
        return("","");
    }
    public static List<SteamGame> Discover(IEnumerable<string> libraries)
    {
        var games=new Dictionary<string,SteamGame>();
        SteamGame Get(string id)=>games.TryGetValue(id,out var g)?g:games[id]=new(id,"App "+id,[],false);
        void Root(string id,string dir){if(Directory.Exists(dir)){var g=Get(id);if(!g.Roots.Contains(dir,StringComparer.OrdinalIgnoreCase))g.Roots.Add(dir);}}
        foreach(var library in libraries.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var apps=Path.Combine(library,"steamapps");if(!Directory.Exists(apps))continue;
            foreach(var manifest in Directory.GetFiles(apps,"appmanifest_*.acf"))
            {
                var id=Path.GetFileNameWithoutExtension(manifest)[12..];if(!Id(id))continue;
                var text=File.ReadAllText(manifest);var actual=Value(text,"appid");if(actual.Length>0&&actual!=id)continue;
                var old=Get(id);var name=WorkshopNames.Clean(Value(text,"name"));var install=Value(text,"installdir");
                bool simple=install.Length>0&&install is not ("." or "..")&&!install.Contains('/')&&!install.Contains('\\')&&!install.Contains(':');
                var dir=simple?Path.Combine(apps,"common",install):"";
                var alt=WorkshopNames.Clean(install.Replace('_',' '));
                games[id]=old with {Name=name.Length>0?name:old.Name,Installed=old.Installed||Directory.Exists(dir),AltName=alt.Length>0?alt:old.AltName};
                if(simple && id=="3167020")Root(id,Path.Combine(dir,"Duckov_Data","Mods"));
            }
            var workshop=Path.Combine(apps,"workshop","content");
            if(Directory.Exists(workshop))foreach(var dir in Directory.GetDirectories(workshop)){var id=Path.GetFileName(dir);if(Id(id))Root(id,dir);}
        }
        return games.Values.OrderBy(g=>g.Name,StringComparer.CurrentCultureIgnoreCase).ThenBy(g=>g.AppId).ToList();
    }
}
