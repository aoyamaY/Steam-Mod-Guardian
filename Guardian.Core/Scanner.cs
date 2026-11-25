using System.Security.Cryptography;
using System.Text.Json;
namespace Guardian.Core;
public sealed class Scanner
{
    public static string DataDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DuckovModGuardian");
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private const long MaxBytes = 64L * 1024 * 1024;
    private static readonly HashSet<string> Exts = new(StringComparer.OrdinalIgnoreCase) { ".dll", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".msi", ".scr", ".com", ".hta", ".asi", ".pyd", ".ocx", ".so", ".dylib", ".luac", ".pyc", ".jar", ".zip" };
    private sealed record CacheData(string Version, Dictionary<string, Analysis> Items);
    private static bool IsHash(string s) => s.Length == 64 && s.All(Uri.IsHexDigit);
    public static string BlacklistPath => Path.Combine(DataDir,"blacklist.txt");
    public static void EnsureData()
    {
        Directory.CreateDirectory(DataDir);
        if (!File.Exists(BlacklistPath)) File.WriteAllText(BlacklistPath,"# 每行一个经核实的 SHA-256（64位十六进制）；# 为注释。默认无黑名单。\n");
    }
    public static void Export(ScanReport report,string path) => File.WriteAllText(path,JsonSerializer.Serialize(report,Json));
    public ScanReport Scan(IEnumerable<string> inputs, bool force, IProgress<ScanProgress>? progress, CancellationToken ct, YaraScan? yara = null, bool useAmsi = false)
    {
        var warnings = new List<string>();
        using var amsi=useAmsi?new AmsiEngine():null;
        if(amsi!=null&&!amsi.IsAvailable)warnings.Add("Windows AMSI 不可用："+amsi.InitializationError+"；静态扫描继续，增强检测未完成。");
        var feed=Community.Load(warnings);
        var domains=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try { var dp=Path.Combine(DataDir,"domains.txt"); if(File.Exists(dp)){if(new FileInfo(dp).Length>1024*1024)throw new IOException("域名名单过大");foreach(var l in File.ReadLines(dp)){var d=l.Split('#')[0].Trim().TrimEnd('.');if(Uri.CheckHostName(d)!=UriHostNameType.Unknown)domains.Add(d);}} }catch(Exception ex){warnings.Add("域名名单不可用："+ex.Message);}
        var cache = new Dictionary<string,Analysis>();
        var blacklist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool canCache = true;
        string cachePath = Path.Combine(DataDir,"cache.json");
        try
        {
            EnsureData();
            foreach(var line in File.ReadLines(BlacklistPath)) { var s=line.Split('#')[0].Trim(); if(IsHash(s)) blacklist.Add(s); else if(s.Length>0) warnings.Add("黑名单有无效条目：已忽略"); }
            if(!force && File.Exists(cachePath) && new FileInfo(cachePath).Length < 64L*1024*1024)
            {
                try { var old=JsonSerializer.Deserialize<CacheData>(File.ReadAllText(cachePath),Json); if(old?.Version==Rules.Version && old.Items!=null) cache=old.Items; }
                catch(Exception ex) { warnings.Add("缓存不可读，已重新分析："+ex.Message); }
            }
        }
        catch(Exception ex) { warnings.Add("本地数据目录不可读写："+ex.Message); canCache=false; }
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var input in inputs) { try { var p=Path.GetFullPath(input.Trim()); if(Directory.Exists(p)) roots.Add(p); else warnings.Add("目录不存在："+p); } catch(Exception ex) { warnings.Add("无效目录："+ex.Message); } }
        if(yara!=null && roots.Any(r=>yara.IsInside(r))) {warnings.Add("YARA 配置位于待扫描目录内，已拒绝运行；请选择独立可信安装位置。");yara=null;}
        var files = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var root in roots)
        {
            var todo=new Stack<string>(); todo.Push(root);
            while(todo.Count>0)
            {
                ct.ThrowIfCancellationRequested(); var dir=todo.Pop(); if(!dirs.Add(dir)) continue;
                try
                {
                    if(!Quarantine.NoReparse(dir)||Quarantine.Inside(dir,Quarantine.DefaultVault)) { warnings.Add("跳过重解析点目录："+dir); continue; }
                    foreach(var sub in Directory.EnumerateDirectories(dir)) todo.Push(sub);
                    foreach(var file in Directory.EnumerateFiles(dir)) if(Exts.Contains(Path.GetExtension(file))||DeepInspection.Scripts.Contains(Path.GetExtension(file))||(PayloadInspection.BlobExtension(Path.GetExtension(file))&&PayloadInspection.Candidate(file))) files.TryAdd(file,root);
                }
                catch(Exception ex) { warnings.Add("目录未完整扫描："+dir+" — "+ex.Message); }
            }
        }
        var rows = new List<ScanRow>(); int done=0;
        foreach(var (file,root) in files.OrderBy(x=>x.Key,StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested(); progress?.Report(new(done,files.Count,file));
            string rel=Path.GetRelativePath(root,file); string first=rel.Split(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar)[0];
            var (appId,workshopId)=SteamCatalog.WorkshopIdentity(file);
            string mod=workshopId.Length>0?workshopId: (first==Path.GetFileName(file)?Path.GetFileName(Path.GetDirectoryName(file))??first:first);
            var localName=WorkshopNames.LocalName(file,root,mod);
            string hash=""; long size=0; bool cached=false; Analysis result;
            try
            {
                if(!Quarantine.NoReparse(file)) throw new IOException("跳过重解析点文件");
                using var fs=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read);
                size=fs.Length;
                if(size>MaxBytes) throw new IOException("超过 64 MiB 分析上限，未完成扫描");
                byte[] bytes=new byte[checked((int)size)]; fs.ReadExactly(bytes);
                hash=Convert.ToHexString(SHA256.HashData(bytes));
                var ext=Path.GetExtension(file).ToLowerInvariant(); var key=ext+":"+hash;
                if(!force && cache.TryGetValue(key,out var hit) && hit!=null) { result=hit; cached=true; }
                else { result=Rules.Inspect(bytes,ext,ct); if(result.Risk!=Risk.Unknown) cache[key]=result; }
                if(blacklist.Contains(hash)) result=result with {Risk=Risk.Critical,Evidence=result.Evidence.Append(new Evidence("命中本地 SHA-256 黑名单",Risk.Critical,"文件",hash)).ToList()};
                result=Community.Apply(result,feed,hash,workshopId);
                result=DeepInspection.Reputation(result,domains);
                if(yara!=null)result=yara.Apply(bytes,result,ct);
                if(amsi!=null)result=amsi.Apply(bytes,hash,ext,result,ct);
                result=DownloadRiskPolicy.Apply(result);
            }
            catch(OperationCanceledException) { throw; }
            catch(Exception ex) { result=new(Risk.Unknown,"未完成",[],ex.Message); }
            rows.Add(new ScanRow(localName,workshopId,file,hash,size,result,cached){AppId=appId,NameSource=localName==mod?"目录/ID":"本地元数据"}); done++;
        }
        // Identical normalized suspicious methods across different package identities are a lead, not a malware verdict.
        string Identity(ScanRow r)=>r.WorkshopId.Length>0?"workshop:"+r.WorkshopId:Path.GetDirectoryName(r.Path)??r.Mod;
        var groups=new Dictionary<string,HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach(var r in rows)foreach(var fingerprint in r.Analysis.Fingerprints??[])
        {
            if(!groups.TryGetValue(fingerprint,out var group))groups[fingerprint]=group=new(StringComparer.OrdinalIgnoreCase);
            group.Add(Identity(r));
        }
        for(int i=0;i<rows.Count;i++)
        {
            var r=rows[i];var matched=(r.Analysis.Fingerprints??[]).Where(f=>groups[f].Count>1).ToList();
            if(matched.Count>0)rows[i]=r with {Similarity=$"共享指纹 {matched.Count}",Analysis=r.Analysis with {Evidence=r.Analysis.Evidence.Append(new Evidence("跨包共享归一化 IL 指纹",Risk.Review,"方法结构",$"{matched.Count} 个方法指纹在其他包中出现；可能是共享库或模板，不代表木马。示例：{matched[0]}")).ToList()}};
        }
        IlSimilarity.Annotate(rows,ct);
        if(canCache) try { var temp=cachePath+"."+Guid.NewGuid().ToString("N")+".tmp"; File.WriteAllText(temp,JsonSerializer.Serialize(new CacheData(Rules.Version,cache.TakeLast(5000).ToDictionary(x=>x.Key,x=>x.Value)),Json)); File.Move(temp,cachePath,true); } catch(Exception ex) { warnings.Add("缓存保存失败："+ex.Message); }
        progress?.Report(new(done,files.Count,"扫描结束"));
        return new(DateTimeOffset.Now,Rules.Version,roots.ToList(),rows,warnings);
    }
}
