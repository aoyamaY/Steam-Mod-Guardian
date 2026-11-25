using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace Guardian.Core;
public static class LocalTools
{
    public static string Run(string executable,IEnumerable<string> args,int seconds,CancellationToken ct)
    {
        var exe=Path.GetFullPath(executable);if(!File.Exists(exe)||!Quarantine.NoReparse(exe)||!exe.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))throw new IOException("请选择独立可信 EXE。");
        var psi=new ProcessStartInfo(exe){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=Path.GetDirectoryName(exe)!};foreach(var a in args)psi.ArgumentList.Add(a);
        using var p=Process.Start(psi)??throw new IOException("分析器启动失败");using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(seconds));
        async Task<string> Drain(StreamReader reader){var buf=new char[4096];var sb=new StringBuilder();int n;while((n=await reader.ReadAsync(buf.AsMemory(),timeout.Token).ConfigureAwait(false))>0){if(sb.Length+n>8*1024*1024){timeout.Cancel();throw new IOException("分析器输出超过限制");}sb.Append(buf,0,n);}return sb.ToString();}
        try{var stdout=Drain(p.StandardOutput);var stderr=Drain(p.StandardError);p.WaitForExitAsync(timeout.Token).GetAwaiter().GetResult();var text=stdout.GetAwaiter().GetResult();_=stderr.GetAwaiter().GetResult();if(p.ExitCode!=0)throw new IOException("分析器退出码："+p.ExitCode);return text;}
        catch{try{if(!p.HasExited){p.Kill(true);p.WaitForExit(2000);}}catch{}ct.ThrowIfCancellationRequested();throw;}
    }
    public static List<string> YaraXMatches(string ndjson)
    {
        var names=new HashSet<string>();foreach(var line in ndjson.Split('\n',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries)){using var doc=JsonDocument.Parse(line);if(!doc.RootElement.TryGetProperty("rules",out var rules)||rules.ValueKind!=JsonValueKind.Array)throw new InvalidDataException("YARA-X 输出格式异常");foreach(var r in rules.EnumerateArray()){var name=r.GetProperty("identifier").GetString();if(name is {Length:>0 and <=128}&&name.All(c=>char.IsAsciiLetterOrDigit(c)||c=='_'))names.Add(name);}}return names.Take(100).ToList();
    }
    public static string Analyze(ScanRow row,string kind,string exe,IEnumerable<string> roots,string? reference,CancellationToken ct)
    {
        if(roots.Any(r=>Quarantine.Inside(exe,r))||Quarantine.Inside(exe,Quarantine.DefaultVault))throw new IOException("拒绝从模组目录或隔离库启动分析器");
        string dir=Path.Combine(Path.GetTempPath(),"guardian-analysis-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(dir);
        try{
            string Copy(string source,string name,string? expected){if(!Quarantine.NoReparse(source))throw new IOException("拒绝重解析点");using var stream=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read);if(stream.Length>64*1024*1024)throw new IOException("文件超过 64 MiB 限制");var bytes=new byte[(int)stream.Length];stream.ReadExactly(bytes);if(expected!=null&&!Convert.ToHexString(SHA256.HashData(bytes)).Equals(expected,StringComparison.OrdinalIgnoreCase))throw new IOException("文件已变化，请重新扫描");string dest=Path.Combine(dir,name);File.WriteAllBytes(dest,bytes);return dest;}
            if(row.Sha256.Length!=64)throw new IOException("缺少已扫描文件哈希");var sample=Copy(row.Path,"sample.bin",row.Sha256);
            switch(kind){
                case "capa": {var text=Run(exe,["-j",sample],120,ct);using var doc=JsonDocument.Parse(text);if(!doc.RootElement.TryGetProperty("rules",out var rules)||rules.ValueKind!=JsonValueKind.Object)throw new IOException("capa JSON 格式不支持");var names=rules.EnumerateObject().Select(r=>r.Name).Take(200);return "capa 能力匹配（不代表恶意）：\n"+string.Join("\n",names);}
                case "FLOSS": {var text=Run(exe,["-j",sample],120,ct);using var doc=JsonDocument.Parse(text);if(!doc.RootElement.TryGetProperty("strings",out var strings))throw new IOException("FLOSS JSON 格式不支持");var hosts=DeepInspection.Hosts(Encoding.UTF8.GetBytes(strings.GetRawText()),ct);return "FLOSS 字符串分析域名（仅显示主机名，不访问）：\n"+(hosts.Count==0?"未发现域名（不代表安全）":string.Join("\n",hosts));}
                case "TLSH": {var hash=Run(exe,["-f",sample],30,ct).Trim().Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()??"";if(!((hash.Length==72&&hash.StartsWith("T1")&&hash[2..].All(Uri.IsHexDigit))||(hash.Length==70&&hash.All(Uri.IsHexDigit))))throw new IOException("TLSH 未能生成有效摘要（文件可能太小或复杂度不足）");string result="TLSH: "+hash;if(reference!=null){var other=Copy(reference,"reference.bin",null);var value=Run(exe,["-c",other,"-f",sample],30,ct).Trim().Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();if(!int.TryParse(value,out var distance)||distance<0)throw new IOException("TLSH 距离输出无效");result+="\n与参考文件的距离："+distance+"（越小越相似，不代表恶意）";}return result;}
                default:throw new ArgumentException("未知分析器");
            }
        }finally{try{Directory.Delete(dir,true);}catch{}}
    }
}
