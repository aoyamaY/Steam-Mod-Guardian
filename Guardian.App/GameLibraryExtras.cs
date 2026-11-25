using Guardian.Core;
using System.Net.Http;
using System.Text.Json;
using System.IO;
namespace Guardian.App;
public partial class MainWindow
{
    private const string LocalNameFile="game-localized-names.json", RiskHistoryFile="game-risk-history-v207.json";
    private Dictionary<string,string>? gameNames;
    private HashSet<string>? riskHistory;
    private Dictionary<string,string> GameNames(){if(gameNames!=null)return gameNames;try{gameNames=ProfileStore.Load<Dictionary<string,string>>(LocalNameFile)??new();}catch(Exception e){StartupLog.Write("Localized names: "+e.Message);gameNames=new();}return gameNames;}
    private HashSet<string> RiskHistory(){if(riskHistory!=null)return riskHistory;try{riskHistory=ProfileStore.Load<HashSet<string>>(RiskHistoryFile)??new();}catch(Exception e){StartupLog.Write("Risk history: "+e.Message);riskHistory=new();}return riskHistory;}
    private void RememberRiskHistory(IEnumerable<ScanRow> rows){try{var ids=RiskHistory();bool changed=false;foreach(var r in rows)if(SteamCatalog.Id(r.AppId)&&(r.Analysis.Risk is Risk.High or Risk.Critical))changed|=ids.Add(r.AppId);if(changed)ProfileStore.Save(RiskHistoryFile,ids);}catch(Exception e){StartupLog.Write("Risk history save: "+e.Message);}}
    private List<SteamGame> WithGameNames(IEnumerable<SteamGame> games)=>games.Select(g=>g with {LocalizedName=GameNames().GetValueOrDefault(g.AppId,"")}).ToList();
    // Public Steam Store endpoint, not a guaranteed documented Web API. Only explicit user requests.
    private async Task<int> FetchGameNamesAsync(IEnumerable<string> ids,CancellationToken token,Action<string> status)
    {
        using var http=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(8)};
        var list=ids.Where(SteamCatalog.Id).Distinct().Take(50).ToArray();int done=0,found=0;
        foreach(var id in list){token.ThrowIfCancellationRequested();status($"正在获取中文名称 {++done}/{list.Length}");try{using var request=CancellationTokenSource.CreateLinkedTokenSource(token);request.CancelAfter(TimeSpan.FromSeconds(8));using var response=await http.GetAsync("https://store.steampowered.com/api/appdetails?appids="+id+"&l=schinese&filters=basic",HttpCompletionOption.ResponseHeadersRead,request.Token);if((int)response.StatusCode==429)break;if(response.IsSuccessStatusCode){using var stream=await response.Content.ReadAsStreamAsync(request.Token);using var bytes=new MemoryStream();var buffer=new byte[8192];int count;while((count=await stream.ReadAsync(buffer.AsMemory(),request.Token))>0){if(bytes.Length+count>2*1024*1024)throw new IOException("商店响应过大");bytes.Write(buffer,0,count);}using var doc=JsonDocument.Parse(bytes.ToArray());if(doc.RootElement.TryGetProperty(id,out var entry)&&entry.TryGetProperty("success",out var ok)&&ok.ValueKind==JsonValueKind.True&&entry.TryGetProperty("data",out var data)&&data.TryGetProperty("name",out var n)&&n.ValueKind==JsonValueKind.String){var value=WorkshopNames.Clean(n.GetString()??"");if(value.Length>0){GameNames()[id]=value;found++;}}}}catch(OperationCanceledException)when(!token.IsCancellationRequested){}catch(HttpRequestException){}catch(JsonException){}catch(IOException){}await Task.Delay(350,token);}
        ProfileStore.Save(LocalNameFile,GameNames());return found;
    }
}
