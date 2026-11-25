using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace Guardian.Core;

// Only user-initiated installation from the official stable GitHub release.
// The GitHub asset digest is required; a missing digest is a hard failure.
public static class YaraInstaller
{
    public sealed record Asset(string Name,Uri Url,string Sha256,long Size);
    const int MaxZip=32*1024*1024, MaxMetadata=2*1024*1024, MaxExtract=96*1024*1024;
    public static string InstallRoot=>Path.Combine(Scanner.DataDir,"tools","yara");
    static bool ValidUri(Uri uri)=>uri.IsAbsoluteUri&&uri.Scheme=="https"&&uri.IsDefaultPort&&uri.UserInfo.Length==0&&uri.Fragment.Length==0;
    static bool Allowed(Uri uri)=>ValidUri(uri)&&(uri.Host is "api.github.com" or "github.com" or "release-assets.githubusercontent.com" or "objects.githubusercontent.com" or "github-releases.githubusercontent.com");
    public static Asset SelectAsset(byte[] metadata)
    {
        using var json=JsonDocument.Parse(metadata);
        var root=json.RootElement;
        if(root.GetProperty("draft").GetBoolean()||root.GetProperty("prerelease").GetBoolean())throw new InvalidDataException("拒绝草稿或预发布版本");
        var tag=root.GetProperty("tag_name").GetString()??"";
        if(!Regex.IsMatch(tag,@"^v?\d+\.\d+\.\d+$"))throw new InvalidDataException("YARA 版本标签异常");
        var assets=new List<Asset>();
        foreach(var a in root.GetProperty("assets").EnumerateArray())
        {
            string name=a.GetProperty("name").GetString()??"";
            if(!Regex.IsMatch(name,@"^yara[-a-zA-Z0-9.]*-win64\.zip$",RegexOptions.IgnoreCase))continue;
            if(a.GetProperty("state").GetString()!="uploaded")continue;
            var size=a.GetProperty("size").GetInt64();
            var digest=a.TryGetProperty("digest",out var d)&&d.ValueKind==JsonValueKind.String?d.GetString():null;
            if(digest==null||!digest.StartsWith("sha256:",StringComparison.OrdinalIgnoreCase)||digest.Length!=71||!digest[7..].All(Uri.IsHexDigit))throw new InvalidDataException("官方发布资源没有有效 SHA-256，拒绝自动安装；请手动核实并配置。");
            if(size<=0||size>MaxZip)throw new InvalidDataException("YARA 安装包大小异常");
            var url=new Uri(a.GetProperty("browser_download_url").GetString()??"");
            if(!ValidUri(url)||url.Host!="github.com"||url.Query.Length!=0||!url.AbsolutePath.Equals($"/VirusTotal/yara/releases/download/{tag}/{name}",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("拒绝非官方发布下载地址");
            assets.Add(new(name,url,digest[7..].ToUpperInvariant(),size));
        }
        if(assets.Count!=1)throw new InvalidDataException("未找到唯一可信的 Windows x64 YARA 安装包");
        return assets[0];
    }
    public static void VerifyPackage(byte[] data,Asset asset)
    {
        if(data.LongLength!=asset.Size||!Convert.ToHexString(SHA256.HashData(data)).Equals(asset.Sha256,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("安装包大小或 SHA-256 不匹配，已拒绝安装");
    }
    static async Task<byte[]> Fetch(HttpClient client,Uri url,int limit,CancellationToken ct)
    {
        for(int hop=0;hop<6;hop++)
        {
            if(!Allowed(url))throw new InvalidDataException("拒绝非官方 HTTPS 下载地址");
            using var response=await client.GetAsync(url,HttpCompletionOption.ResponseHeadersRead,ct).ConfigureAwait(false);
            if((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
            {var next=response.Headers.Location??throw new IOException("重定向缺少地址");url=next.IsAbsoluteUri?next:new Uri(url,next);continue;}
            response.EnsureSuccessStatusCode();
            if(response.Content.Headers.ContentLength>limit)throw new IOException("下载内容超过大小上限");
            using var stream=await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var ms=new MemoryStream();byte[] buf=new byte[65536];int n;
            while((n=await stream.ReadAsync(buf.AsMemory(),ct).ConfigureAwait(false))>0){if(ms.Length+n>limit)throw new IOException("下载内容超过大小上限");ms.Write(buf,0,n);}
            return ms.ToArray();
        }
        throw new IOException("下载重定向过多");
    }
    // Extract only the official scanner and DLL dependencies beside it. No archive-supplied path is written.
    public static string ExtractEngine(byte[] data,string directory,CancellationToken ct=default)
    {
        using var archive=new ZipArchive(new MemoryStream(data,false),ZipArchiveMode.Read);
        if(archive.Entries.Count>256)throw new InvalidDataException("安装包条目过多");
        var files=archive.Entries.Select(e=>(Entry:e,Name:e.FullName.Replace('\\','/'))).ToList();
        foreach(var f in files)
        {
            var parts=f.Name.TrimEnd('/').Split('/');
            if(parts.Any(p=>p.Length==0||p=="."||p==".."||p.Contains(':'))||((f.Entry.ExternalAttributes>>16)&0xF000)==0xA000||(f.Entry.ExternalAttributes&0x400)!=0)throw new InvalidDataException("安装包含不安全路径或链接");
        }
        var exe=files.Where(f=>f.Name.Split('/').Last().Equals("yara64.exe",StringComparison.OrdinalIgnoreCase)).ToList();
        if(exe.Count!=1)throw new InvalidDataException("安装包没有唯一的 yara64.exe");
        var exePath=exe[0].Name;string prefix=exePath[..(exePath.LastIndexOf('/')+1)];
        var selected=files.Where(f=>f.Name.StartsWith(prefix,StringComparison.Ordinal)&&!f.Name[prefix.Length..].Contains('/')&&(f.Name==exePath||f.Name.EndsWith(".dll",StringComparison.OrdinalIgnoreCase))).ToList();
        var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);long total=0;
        foreach(var f in selected)
        {
            ct.ThrowIfCancellationRequested();string name=f.Name[prefix.Length..];
            if(!Regex.IsMatch(name,@"^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.(?:dll|exe)$",RegexOptions.IgnoreCase)||!names.Add(name)||Regex.IsMatch(name.Split('.')[0],@"^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$",RegexOptions.IgnoreCase))throw new InvalidDataException("安装包文件名异常");
            if(f.Entry.Length<=0||f.Entry.Length>MaxExtract-total)throw new InvalidDataException("解包超过大小上限");total+=f.Entry.Length;
            using var input=f.Entry.Open();using var output=new FileStream(Path.Combine(directory,name),FileMode.CreateNew,FileAccess.Write,FileShare.None);
            byte[] buf=new byte[65536];long written=0;int n;while((n=input.Read(buf,0,buf.Length))>0){ct.ThrowIfCancellationRequested();written+=n;if(written>f.Entry.Length)throw new InvalidDataException("解包实际长度异常");output.Write(buf,0,n);}if(written!=f.Entry.Length)throw new InvalidDataException("解包长度不匹配");
        }
        return Path.Combine(directory,exePath[prefix.Length..]);
    }
    public static async Task<YaraScan> InstallAsync(string rules,IEnumerable<string> scanRoots,IProgress<string>? progress,CancellationToken ct)
    {
        var roots=scanRoots.ToArray();var target=Path.GetFullPath(InstallRoot);rules=Path.GetFullPath(rules);
        if(roots.Any(r=>Quarantine.Inside(target,r)||Quarantine.Inside(r,target)||Quarantine.Inside(rules,r)))throw new IOException("YARA 安装位置或规则与扫描目录重叠，请缩小扫描范围。");
        if(!File.Exists(rules)||!Quarantine.NoReparse(rules))throw new IOException("内置 YARA 规则缺失或路径不可信，请重新完整解压软件。");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromMinutes(2));var token=timeout.Token;
        using var client=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(45)};
        client.DefaultRequestHeaders.UserAgent.ParseAdd("SteamModGuardian/2.0.5");
        progress?.Report("正在获取 YARA 官方稳定版本…");
        var meta=await Fetch(client,new Uri("https://api.github.com/repos/VirusTotal/yara/releases/latest"),MaxMetadata,token).ConfigureAwait(false);
        var asset=SelectAsset(meta);progress?.Report("正在下载 "+asset.Name+"…");
        var bytes=await Fetch(client,asset.Url,MaxZip,token).ConfigureAwait(false);VerifyPackage(bytes,asset);
        token.ThrowIfCancellationRequested();progress?.Report("SHA-256 校验通过，正在安全解包…");
        for(string? parent=target;parent!=null;parent=Path.GetDirectoryName(parent))if(Directory.Exists(parent)&&!Quarantine.NoReparse(parent))throw new IOException("拒绝重解析点安装路径");
        Directory.CreateDirectory(target);if(!Quarantine.NoReparse(target))throw new IOException("拒绝重解析点安装路径");
        string stage=Path.Combine(target,Guid.NewGuid().ToString("N"));Directory.CreateDirectory(stage);
        bool success=false;
        try
        {
            if(!Quarantine.NoReparse(stage))throw new IOException("安装目录不可信");
            var exe=ExtractEngine(bytes,stage,token);var candidate=new YaraScan(exe,rules);
            progress?.Report("正在测试引擎及内置规则…");
            var sample=System.Text.Encoding.UTF8.GetBytes("Steam Mod Guardian harmless configuration test");
            var original=new Analysis(Risk.Clear,"配置测试",[]);
            var check=candidate.Apply(sample,original,token);
            if(check.YaraStatus.StartsWith("失败："))throw new IOException(check.YaraStatus);
            var testRule=Path.Combine(stage,"guardian_selftest.yar");
            try{File.WriteAllText(testRule,"rule Guardian_Install_SelfTest { strings: $s = \"Steam Mod Guardian harmless configuration test\" condition: $s }");var hit=new YaraScan(exe,testRule).Apply(sample,original,token);if(!hit.Evidence.Any(e=>e.Rule=="YARA 特征命中"&&e.Detail.StartsWith("Guardian_Install_SelfTest",StringComparison.Ordinal)))throw new IOException("YARA 无害阳性自检未命中："+hit.YaraStatus);}
            finally{File.Delete(testRule);}
            token.ThrowIfCancellationRequested();success=true;return candidate;
        }
        finally{if(!success)try{Directory.Delete(stage,true);}catch{}}
    }
}
