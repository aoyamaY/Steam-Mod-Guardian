using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
namespace Guardian.Core;
public sealed record UserProfile(List<string> SelectedIds,Dictionary<string,List<string>> ExtraRoots,List<string> UnassignedRoots,bool Monitor,bool QueryTitles);
public sealed record SavedBaseline(string Key, List<ScanRow> Rows,List<string> Changes);
public static class ProfileStore
{
    static readonly JsonSerializerOptions Opt=new(){WriteIndented=false};
    static string PathFor(string name)=>Path.Combine(Scanner.DataDir,name);
    public static T? Load<T>(string name) where T:class {var path=PathFor(name);if(!File.Exists(path))return null;if(new FileInfo(path).Length>32*1024*1024)throw new IOException("配置/历史超过 32 MiB");return JsonSerializer.Deserialize<T>(File.ReadAllText(path),Opt);}
    public static void Save<T>(string name,T data){Scanner.EnsureData();var raw=JsonSerializer.SerializeToUtf8Bytes(data,Opt);if(raw.Length>32*1024*1024)throw new IOException("配置/历史超过 32 MiB");var path=PathFor(name);var tmp=path+"."+Guid.NewGuid().ToString("N")+".tmp";try{File.WriteAllBytes(tmp,raw);File.Move(tmp,path,true);}finally{if(File.Exists(tmp))File.Delete(tmp);}}
    public static string ScopeFile(string key)=>"baseline-"+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))+".json";
    public static List<string> RootsFor(IEnumerable<SteamGame> games,Dictionary<string,List<string>> extra,IEnumerable<string> unassigned)=>games.SelectMany(g=>g.Roots.Concat(extra.TryGetValue(g.AppId,out var roots)?roots:[])).Concat(unassigned).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}
