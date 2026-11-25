using System.Net;
using System.Text.Json;
namespace Guardian.Core;
public sealed record ReputationResult(string Status,int Malicious=0,int Suspicious=0,int Harmless=0,int Undetected=0,DateTimeOffset? AnalysisTime=null);
public static class ReputationClient
{
    public static async Task<ReputationResult> QueryAsync(string key,string value,bool domain,CancellationToken ct=default)
    {
        if(string.IsNullOrWhiteSpace(key))throw new ArgumentException("请输入 VirusTotal API Key");
        if(domain?Uri.CheckHostName(value)!=UriHostNameType.Dns:value.Length!=64||!value.All(Uri.IsHexDigit))throw new ArgumentException("无效查询标识");
        using var http=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(20),MaxResponseContentBufferSize=2*1024*1024};
        using var request=new HttpRequestMessage(HttpMethod.Get,"https://www.virustotal.com/api/v3/"+(domain?"domains/":"files/")+Uri.EscapeDataString(value));request.Headers.Add("x-apikey",key.Trim());
        using var response=await http.SendAsync(request,ct);
        if(response.StatusCode==HttpStatusCode.NotFound)return new("未收录（不是安全结论）");if((int)response.StatusCode==429)return new("查询额度/频率限制");if(!response.IsSuccessStatusCode)return new("HTTP "+(int)response.StatusCode+"（查询失败）");
        using var doc=JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct));var a=doc.RootElement.GetProperty("data").GetProperty("attributes");
        if(!a.TryGetProperty("last_analysis_stats",out var stats))return new("未提供检测统计");
        int N(string name)=>stats.TryGetProperty(name,out var j)&&j.TryGetInt32(out int v)?v:0;
        DateTimeOffset? date=a.TryGetProperty("last_analysis_date",out var dt)&&dt.TryGetInt64(out var sec)?DateTimeOffset.FromUnixTimeSeconds(sec):null;
        return new("已收录（引擎意见，不是定论）",N("malicious"),N("suspicious"),N("harmless"),N("undetected"),date);
    }
}
