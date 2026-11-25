using System.Security.Cryptography;
using System.Text.Json;
namespace Guardian.Core;
public sealed record CommunityEntry(string Kind,string Value,string Reason);
public sealed record CommunityFeed(long Version,DateTimeOffset ExpiresUtc,List<CommunityEntry> Entries);
public static class Community
{
    public static string FeedPath=>Path.Combine(Scanner.DataDir,"community-signed.json");
    public static string KeyPath=>Path.Combine(Scanner.DataDir,"community-public.pem");
    public static string UrlPath=>Path.Combine(Scanner.DataDir,"community-url.txt");
    private sealed record Envelope(string Payload,string Signature);
    public static CommunityFeed Verify(byte[] raw,string pem)
    {
        if(raw.Length>4*1024*1024)throw new InvalidDataException("社区名单超出 4 MiB");
        var env=JsonSerializer.Deserialize<Envelope>(raw)??throw new InvalidDataException("无效签名包");
        var payload=Convert.FromBase64String(env.Payload);var signature=Convert.FromBase64String(env.Signature);
        using var rsa=RSA.Create();rsa.ImportFromPem(pem);
        if(rsa.KeySize<2048||!rsa.VerifyData(payload,signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1))throw new CryptographicException("社区名单签名无效");
        var feed=JsonSerializer.Deserialize<CommunityFeed>(payload)??throw new InvalidDataException("名单格式错误");
        if(feed.Version<1||feed.Entries==null||feed.Entries.Count>20000||feed.ExpiresUtc<=DateTimeOffset.UtcNow)throw new InvalidDataException("名单过期或格式无效");
        foreach(var e in feed.Entries)if(e==null||e.Value==null||e.Reason==null||e.Reason.Length>500||!(e.Kind is "sha256" or "il-v1" or "workshop")||(e.Kind=="workshop"?!ulong.TryParse(e.Value,out _):e.Value.Length!=64||!e.Value.All(Uri.IsHexDigit)))throw new InvalidDataException("名单含无效记录");
        return feed;
    }
    public static CommunityFeed? Load(List<string> warnings)
    {
        if(!File.Exists(FeedPath))return null;
        try { if(new FileInfo(FeedPath).Length>4*1024*1024||new FileInfo(KeyPath).Length>65536)throw new InvalidDataException("社区配置过大");return Verify(File.ReadAllBytes(FeedPath),File.ReadAllText(KeyPath)); }
        catch(Exception ex){warnings.Add("社区名单未使用："+ex.Message);return null;}
    }
    public static async Task<long> SyncAsync(CancellationToken ct)
    {
        Scanner.EnsureData(); var url=File.ReadAllText(UrlPath).Trim(); var pem=File.ReadAllText(KeyPath);
        if(!Uri.TryCreate(url,UriKind.Absolute,out var uri)||uri.Scheme!="https"||uri.UserInfo.Length!=0)throw new InvalidDataException("请配置可信 HTTPS 名单地址");
        using var client=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(20),MaxResponseContentBufferSize=4*1024*1024};
        var bytes=await client.GetByteArrayAsync(uri,ct); var feed=Verify(bytes,pem);
        // Persist a monotonic version per configured signing key. Same version cannot silently replace content.
        var versionPath=Path.Combine(Scanner.DataDir,"community-version-"+Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(pem)))+".txt");
        if(File.Exists(versionPath)&&long.TryParse(File.ReadAllText(versionPath),out long old)&&feed.Version<old)throw new InvalidDataException("拒绝旧版本名单");
        var previous=Load([]); if(previous!=null&&feed.Version==previous.Version&&File.Exists(FeedPath)&&!File.ReadAllBytes(FeedPath).SequenceEqual(bytes))throw new InvalidDataException("相同版本内容不同，请发布新版本");
        var tmp=FeedPath+".tmp"; File.WriteAllBytes(tmp,bytes);File.Move(tmp,FeedPath,true);File.WriteAllText(versionPath,feed.Version.ToString());return feed.Version;
    }
    public static Analysis Apply(Analysis original,CommunityFeed? feed,string hash,string id)
    {
        if(feed==null)return original;
        var evidence=new List<Evidence>(original.Evidence);var risk=original.Risk;
        var fingerprints=(original.Fingerprints??[]).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach(var entry in feed.Entries)
        {
            bool match=entry.Kind switch {"sha256"=>entry.Value.Equals(hash,StringComparison.OrdinalIgnoreCase),"il-v1"=>fingerprints.Contains(entry.Value),"workshop"=>id==entry.Value,_=>false};if(!match)continue;
            var level=entry.Kind=="sha256"?Risk.Critical:Risk.High;
            if(risk==Risk.Unknown||(int)risk<(int)level)risk=level;
            evidence.Add(new("社区名单："+entry.Kind,level,"签名名单 v"+feed.Version,entry.Reason+"；"+entry.Value));
            if(evidence.Count>=330)break;
        }
        return original with {Risk=risk,Evidence=evidence};
    }
}
