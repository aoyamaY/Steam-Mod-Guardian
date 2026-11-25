using System.Security.Cryptography;
using System.Text.Json;
namespace Guardian.Core;
public sealed record QuarantineEntry(string Id,string OriginalPath,string Root,string Sha256,string Game,string Mod,DateTimeOffset Time);
public static class Quarantine
{
    public static string DefaultVault => Path.Combine(Scanner.DataDir,"quarantine");
    public static bool Inside(string path,string root)
    {
        var full=Path.GetFullPath(path);var r=Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return full.Equals(r,StringComparison.OrdinalIgnoreCase)||full.StartsWith(Path.EndsInDirectorySeparator(r)?r:r+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase);
    }
    public static bool NoReparse(string path)
    {
        for(string? p=Path.GetFullPath(path);p!=null;p=Path.GetDirectoryName(p))
            if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)return false;
        return true;
    }
    private static string Hash(Stream s)=>Convert.ToHexString(SHA256.HashData(s));
    private static void Require(bool ok,string message){if(!ok)throw new IOException(message);}
    private static void ValidateSource(string path,string root,string vault)
    {
        Require(Inside(path,root)&&!Path.GetFullPath(path).Equals(Path.GetFullPath(root),StringComparison.OrdinalIgnoreCase),"文件不在原扫描目录内。");
        Require(!Inside(path,vault)&&!Inside(vault,root),"不能隔离隔离库内文件或包含隔离库的扫描目录。");
        Require(NoReparse(root)&&NoReparse(Path.GetDirectoryName(path)!),"拒绝重解析点路径。");
    }
    public static QuarantineEntry Move(ScanRow row,IEnumerable<string> roots,string? vault=null)
    {
        vault=Path.GetFullPath(vault??DefaultVault);
        Require(row.Analysis.Risk is Risk.High or Risk.Critical,"只允许隔离已扫描的高危文件。");
        Require(row.Sha256.Length==64&&row.Sha256.All(Uri.IsHexDigit),"缺少有效扫描哈希，请重新扫描。");
        var path=Path.GetFullPath(row.Path);
        var root=roots.Select(Path.GetFullPath).Where(r=>Inside(path,r)).OrderByDescending(r=>r.Length).FirstOrDefault()??throw new IOException("文件不在本次扫描范围内。");
        ValidateSource(path,root,vault);Require(NoReparse(path),"拒绝重解析点文件。");
        Directory.CreateDirectory(vault);Require(NoReparse(vault),"拒绝重解析点隔离库。");
        var entry=new QuarantineEntry(Guid.NewGuid().ToString("N"),path,root,row.Sha256,row.GameName,row.Mod,DateTimeOffset.Now);
        var dir=Path.Combine(vault,entry.Id);Directory.CreateDirectory(dir);Require(NoReparse(dir),"隔离库路径异常。");
        var payload=Path.Combine(dir,"payload.bin");var metadata=Path.Combine(dir,"entry.json");
        // Journal first. Hold a handle denying writes while verifying and moving; external races are not a security boundary.
        using(var source=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete))
        {
            Require(Hash(source).Equals(row.Sha256,StringComparison.OrdinalIgnoreCase),"文件已变化，请重新扫描。");
            using(var journal=new FileStream(metadata,FileMode.CreateNew,FileAccess.Write,FileShare.None)){JsonSerializer.Serialize(journal,entry);journal.Flush(true);}
            File.Move(path,payload,false);
        }
        Require(File.Exists(payload)&&NoReparse(payload),"隔离移动未完成，请检查隔离库及原目录。");
        using(var saved=File.OpenRead(payload))Require(Hash(saved).Equals(entry.Sha256,StringComparison.OrdinalIgnoreCase),"隔离文件校验失败，保留文件和记录供人工处理。");
        Require(!File.Exists(path),"原路径仍存在文件，可能被 Steam 恢复；请重新扫描。");
        return entry;
    }
    public static List<QuarantineEntry> List(string? vault=null)
    {
        vault=Path.GetFullPath(vault??DefaultVault);if(!Directory.Exists(vault))return [];
        Require(NoReparse(vault),"隔离库路径异常。");var entries=new List<QuarantineEntry>();
        foreach(var dir in Directory.GetDirectories(vault))
        {
            var id=Path.GetFileName(dir);if(!Guid.TryParseExact(id,"N",out _)||!NoReparse(dir))continue;
            var meta=Path.Combine(dir,"entry.json");var payload=Path.Combine(dir,"payload.bin");
            if(!File.Exists(meta)||!File.Exists(payload)||!NoReparse(meta)||!NoReparse(payload)||new FileInfo(meta).Length>65536)continue;
            var e=JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(meta));if(e!=null&&e.Id==id)entries.Add(e);
        }
        return entries.OrderByDescending(e=>e.Time).ToList();
    }
    public static void Restore(QuarantineEntry entry,string? vault=null)
    {
        vault=Path.GetFullPath(vault??DefaultVault);Require(Guid.TryParseExact(entry.Id,"N",out _),"隔离 ID 无效。");
        var dir=Path.Combine(vault,entry.Id);var payload=Path.Combine(dir,"payload.bin");var meta=Path.Combine(dir,"entry.json");
        Require(NoReparse(payload)&&NoReparse(meta),"隔离文件路径异常。");
        var stored=JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(meta));Require(stored==entry,"隔离记录已变化。");
        ValidateSource(entry.OriginalPath,entry.Root,vault);
        Require(!File.Exists(entry.OriginalPath)&&!Directory.Exists(entry.OriginalPath),"原路径已存在，拒绝覆盖。请先人工检查 Steam 是否重新下载。");
        using(var source=new FileStream(payload,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete))
        {
            Require(Hash(source).Equals(entry.Sha256,StringComparison.OrdinalIgnoreCase),"隔离文件哈希不符，拒绝恢复。");
            File.Move(payload,entry.OriginalPath,false);
        }
        Require(!File.Exists(payload)&&File.Exists(entry.OriginalPath),"恢复未完成，请人工检查。");
        // Keep the journal for audit; restored entries no longer appear in the active list.
    }
}
