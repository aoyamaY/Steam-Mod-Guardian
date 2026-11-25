using System.Diagnostics;
namespace Guardian.Core;
public sealed class YaraScan(string executable,string rules,bool useYaraX=false)
{
    public bool IsInside(string root)
    {
        string prefix=Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar)+Path.DirectorySeparatorChar;
        return Path.GetFullPath(executable).StartsWith(prefix,StringComparison.OrdinalIgnoreCase)||Path.GetFullPath(rules).StartsWith(prefix,StringComparison.OrdinalIgnoreCase);
    }
    public Analysis Apply(byte[] bytes,Analysis original,CancellationToken ct)
    {
        string? temp=null;
        try {
            // Only explicit, user-selected trusted executable and rules; never look in mod directories.
            var exe=Path.GetFullPath(executable);var rule=Path.GetFullPath(rules);
            if(!File.Exists(exe)||!File.Exists(rule))throw new FileNotFoundException("YARA 程序或规则不存在");
            if(!Quarantine.NoReparse(exe)||!Quarantine.NoReparse(rule))throw new IOException("YARA 配置不能使用重解析点路径");
            temp=Path.Combine(Path.GetTempPath(),"guardian-"+Guid.NewGuid().ToString("N")+".sample");
            using(var f=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None))f.Write(bytes);
            if(useYaraX){var found=LocalTools.YaraXMatches(LocalTools.Run(exe,["scan","--output-format","ndjson","--timeout","5",rule,temp],15,ct));var evidence=original.Evidence.Concat(found.Select(x=>new Evidence("YARA-X 特征命中",Risk.Review,"文件",x+"（需复核）"))).ToList();return original with {Risk=found.Count>0&&original.Risk==Risk.Clear?Risk.Review:original.Risk,Evidence=evidence,YaraStatus=found.Count==0?"YARA-X 未命中":$"YARA-X 命中 {found.Count} 条"};}
            var psi=new ProcessStartInfo(exe){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=Path.GetDirectoryName(exe)!};
            foreach(var arg in new[]{"-a","5",rule,temp})psi.ArgumentList.Add(arg);
            using var p=Process.Start(psi)??throw new IOException("YARA 无法启动");
            var output=p.StandardOutput.ReadToEndAsync();var error=p.StandardError.ReadToEndAsync();
            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(10));
            try{p.WaitForExitAsync(timeout.Token).GetAwaiter().GetResult();}catch{try{p.Kill(true);}catch{}ct.ThrowIfCancellationRequested();throw new IOException("YARA 超时");}
            var text=output.GetAwaiter().GetResult();var stderr=error.GetAwaiter().GetResult();
            if(p.ExitCode!=0)throw new IOException("YARA 退出码 "+p.ExitCode+": "+stderr[..Math.Min(stderr.Length,300)]);
            var matches=text.Split('\n',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries).Select(x=>x.Split(' ',2)[0]).Where(x=>x.All(c=>char.IsAsciiLetterOrDigit(c)||c=='_')).Distinct().Take(50).ToArray();
            var ev=new List<Evidence>(original.Evidence);foreach(var match in matches)ev.Add(new("YARA 特征命中",Risk.Review,"文件",match+"（特征命中不等于恶意定论）"));
            var risk=original.Risk==Risk.Clear&&matches.Length>0?Risk.Review:original.Risk;
            return original with {Risk=risk,Evidence=ev,YaraStatus=matches.Length==0?"未命中":$"命中 {matches.Length} 条"};
        } catch(OperationCanceledException){throw;}
        catch(Exception ex){return original with {YaraStatus="失败："+ex.Message,Risk=original.Risk==Risk.Clear?Risk.Unknown:original.Risk};}
        finally{if(temp!=null)try{File.Delete(temp);}catch{}}
    }
}
