using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
namespace Guardian.Core;
public static class WorkshopNames
{
    public static string LocalName(string file, string root, string fallback)
    {
        var dir=Path.GetDirectoryName(file); string boundary=Path.GetFullPath(root);
        while(dir!=null && (dir.Equals(boundary,StringComparison.OrdinalIgnoreCase)||dir.StartsWith(boundary.TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)))
        {
            try {
                var p=Path.Combine(dir,"info.ini");
                if(File.Exists(p) && Quarantine.NoReparse(p) && new FileInfo(p).Length<=65536)
                {
                    string? name=null;
                    foreach(var line in File.ReadLines(p)) { int i=line.IndexOf('='); if(i<1)continue; var key=line[..i].Trim(); var value=Clean(line[(i+1)..].Trim().Trim('"')); if(value.Length==0)continue; if(key.Equals("displayName",StringComparison.OrdinalIgnoreCase))return value; if(key.Equals("name",StringComparison.OrdinalIgnoreCase))name=value; }
                    if(name!=null)return name;
                }
                // Common offline metadata used by other games. No DTD, external entities or execution.
                var modInfo=Path.Combine(dir,"mod.info");
                if(File.Exists(modInfo)&&Quarantine.NoReparse(modInfo)&&new FileInfo(modInfo).Length<=65536)
                    foreach(var line in File.ReadLines(modInfo)){int eq=line.IndexOf('=');if(eq>0&&line[..eq].Trim().Equals("name",StringComparison.OrdinalIgnoreCase)){var name=Clean(line[(eq+1)..].Trim());if(name.Length>0)return name;}}
                var about=Path.Combine(dir,"About","About.xml");
                if(File.Exists(about)&&Quarantine.NoReparse(about)&&new FileInfo(about).Length<=65536)
                {using var reader=XmlReader.Create(about,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=65536});var doc=XDocument.Load(reader);var name=Clean(doc.Root?.Element("name")?.Value??"");if(name.Length>0)return name;}
            } catch { }
            if(dir.Equals(boundary,StringComparison.OrdinalIgnoreCase))break;
            dir=Path.GetDirectoryName(dir);
        }
        return fallback;
    }
    public static string Clean(string s) => new string(s.Where(c=>!char.IsControl(c) && char.GetUnicodeCategory(c)!=System.Globalization.UnicodeCategory.Format).Take(200).ToArray()).Trim();
    public static async Task<ScanReport> ResolveAsync(ScanReport report,CancellationToken ct)
    {
        var ids=report.Files.Select(x=>x.WorkshopId).Where(x=>ulong.TryParse(x,out _)).Distinct().ToArray();
        var titles=new Dictionary<string,string>();
        using var client=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(12),MaxResponseContentBufferSize=4*1024*1024};
        foreach(var batch in ids.Chunk(50))
        {
            ct.ThrowIfCancellationRequested();
            try {
                var fields=new List<KeyValuePair<string,string>>{new("itemcount",batch.Length.ToString(System.Globalization.CultureInfo.InvariantCulture))};
                for(int i=0;i<batch.Length;i++) fields.Add(new($"publishedfileids[{i}]",batch[i]));
                using var content=new FormUrlEncodedContent(fields);
                using var response=await client.PostAsync("https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/",content,ct); response.EnsureSuccessStatusCode();
                using var doc=JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct));
                foreach(var item in doc.RootElement.GetProperty("response").GetProperty("publishedfiledetails").EnumerateArray())
                {
                    if(!item.TryGetProperty("result",out var result)||result.GetInt32()!=1||!item.TryGetProperty("publishedfileid",out var id)||!item.TryGetProperty("title",out var title))continue;
                    var key=id.ValueKind==JsonValueKind.String?id.GetString():id.GetRawText(); var value=Clean(title.GetString()??"");
                    if(key!=null&&batch.Contains(key)&&value.Length>0)titles[key]=value;
                }
            } catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
            catch(Exception ex){report.Warnings.Add("Steam 标题查询失败，保留本地名称/ID："+ex.Message);break;}
        }
        if(titles.Count<ids.Length)report.Warnings.Add($"{ids.Length-titles.Count} 个工坊项目未取得在线标题，使用本地名称或 ID。");
        return report with {Files=report.Files.Select(r=>titles.TryGetValue(r.WorkshopId,out var title)?r with {Mod=title,NameSource="Steam 工坊"}:r).ToList()};
    }
}
