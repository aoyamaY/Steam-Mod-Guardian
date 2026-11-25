using System.IO.Compression;
using Mono.Cecil;
namespace Guardian.Core;
// Bounded static inspection, never extracts files, resolves assemblies or runs embedded content.
public static class PayloadInspection
{
    public static bool Zip(byte[] b)=>b.Length>=4&&b[0]==80&&b[1]==75&&((b[2]==3&&b[3]==4)||(b[2]==5&&b[3]==6)||(b[2]==7&&b[3]==8));
    public static bool BlobExtension(string ext)=>ext.ToLowerInvariant() is ".bin" or ".dat" or ".bytes";
    public static bool Candidate(string path){try{if(!Quarantine.NoReparse(path))return true;using var f=File.OpenRead(path);var b=new byte[4];return f.Read(b,0,4)==4&&(DeepInspection.IsPe(b)||Zip(b));}catch{return true;}}
    const int Limit=32*1024*1024, Single=8*1024*1024;
    static string SafeName(string name)=>new string(name.Take(160).Select(c=>char.IsControl(c)?' ':c).ToArray());
    internal static string StrongerDownload(string a,string b){string[] order=["未发现","普通联网（未见落盘）","接收数据/流（未见落盘）","联网+写入（待核实）","疑似下载落盘","直接文件下载 API"];return Array.IndexOf(order,b)>Array.IndexOf(order,a)?b:a;}
    public static Analysis Inspect(Analysis original,byte[] bytes,string ext,CancellationToken ct)
    {
        bool archive=Zip(bytes),managed=false;
        if(!archive&&DeepInspection.IsPe(bytes))try{managed=DeepInspection.IsManaged(bytes);}catch{return original;}
        if(!archive&&!managed)return original;
        var a=original;int budget=Limit,count=0;
        void Incomplete(string reason){a=a with {Risk=RiskFusion.Merge(a.Risk,Risk.Unknown),Error=(a.Error==null?"":a.Error+"；")+reason};}
        void Child(string name,byte[] data,string extension)
        {
            ct.ThrowIfCancellationRequested();string label=SafeName(name);
            if(Zip(data)){Incomplete("嵌套归档未递归分析："+label);return;}
            if(DeepInspection.IsPe(data)){if(extension is not (".exe" or ".scr" or ".com"))extension=".dll";}
            else if(!DeepInspection.Scripts.Contains(extension)){Incomplete("内部候选文件无法识别："+label);return;}
            var child=Rules.Inspect(data,extension,ct,false);
            var risk=RiskFusion.Merge(child.Risk,Risk.Review);
            if(child.Kind=="托管 DLL") {using var nested=ModuleDefinition.ReadModule(new MemoryStream(data,false));if(nested.Resources.OfType<EmbeddedResource>().Any())Incomplete("内部程序集的下一层嵌入资源未检查："+label);}
            var ev=a.Evidence.Append(new Evidence("内部可执行内容",Risk.Review,label,"已静态分析；未提取到磁盘、未执行")).Concat(child.Evidence.Take(40).Select(e=>e with {Method=label+" / "+e.Method})).OrderByDescending(e=>e.Risk is Risk.Critical?4:e.Risk is Risk.High?3:e.Risk is Risk.Unknown?2:1).Take(600).ToList();
            a=a with {Risk=RiskFusion.Merge(a.Risk,risk),Evidence=ev,Download=StrongerDownload(a.Download,child.Download),Hosts=(a.Hosts??[]).Concat(child.Hosts??[]).Distinct(StringComparer.OrdinalIgnoreCase).Take(512).ToList(),Fingerprints=(a.Fingerprints??[]).Concat(child.Fingerprints??[]).Distinct().Take(4096).ToList(),FuzzyFingerprints=(a.FuzzyFingerprints??[]).Concat(child.FuzzyFingerprints??[]).Distinct().Take(256).ToList()};
            if(child.Error!=null)Incomplete("内部内容分析不完整："+label);
        }
        byte[] Read(Stream s,long length){if(length<0||length>Single||length>budget)throw new InvalidDataException("内部载荷超过扫描上限");var b=new byte[(int)length];s.ReadExactly(b);budget-=b.Length;return b;}
        try
        {
            if(archive)
            {
                using var z=new ZipArchive(new MemoryStream(bytes,false),ZipArchiveMode.Read);
                a=a with {Kind="ZIP / JAR 归档"};
                foreach(var e in z.Entries){ct.ThrowIfCancellationRequested();if(++count>512){Incomplete("归档条目超过 512 项");break;}if(e.Name.Length==0)continue;string x=Path.GetExtension(e.Name).ToLowerInvariant();
                    if(x is ".class" or ".so" or ".dylib" or ".pyc" or ".luac" or ".7z" or ".rar"){Incomplete("存在暂不支持的内部代码/归档");continue;}
                    using var s=e.Open();var header=new byte[4];int n=s.ReadAtLeast(header,4,false);bool candidate=n>=2&&DeepInspection.IsPe(header)||n==4&&Zip(header)||DeepInspection.Scripts.Contains(x)||x is ".dll" or ".exe" or ".zip" or ".jar";
                    if(!candidate)continue;
                    if(e.Length>Single||e.Length>budget||e.Length>Math.Max(1,e.CompressedLength)*200){Incomplete("归档载荷超出大小或压缩比限制");continue;}
                    var data=new byte[(int)e.Length];Array.Copy(header,data,n);s.ReadExactly(data.AsSpan(n));budget-=data.Length;Child(e.FullName,data,x);
                }
            }
            else
            {
                using var mod=ModuleDefinition.ReadModule(new MemoryStream(bytes,false),new ReaderParameters{ReadingMode=ReadingMode.Deferred,ReadSymbols=false});
                foreach(var r in mod.Resources.OfType<EmbeddedResource>()){ct.ThrowIfCancellationRequested();if(++count>256){Incomplete("嵌入资源超过 256 项");break;}using var s=r.GetResourceStream();if(!s.CanSeek){Incomplete("嵌入资源流不可定位");continue;}var header=new byte[4];int n=s.ReadAtLeast(header,4,false);s.Position=0;var x=Path.GetExtension(r.Name).ToLowerInvariant();if(!(n>=2&&DeepInspection.IsPe(header)||n==4&&Zip(header)||DeepInspection.Scripts.Contains(x)))continue; if(s.Length>Single||s.Length>budget){Incomplete("嵌入载荷超过扫描上限");continue;}Child(r.Name,Read(s,s.Length),x);}
            }
        }catch(OperationCanceledException){throw;}catch(Exception ex){Incomplete("内部载荷检查失败："+ex.GetType().Name);}
        return a;
    }
}
