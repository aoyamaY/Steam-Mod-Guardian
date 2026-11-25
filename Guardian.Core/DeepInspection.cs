using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;
using System.Buffers.Binary;
using System.Net;
namespace Guardian.Core;
public static class DeepInspection
{
    public static readonly HashSet<string> Scripts=new(StringComparer.OrdinalIgnoreCase){".lua",".py",".pyw",".js",".mjs",".cjs",".ts",".ps1",".psm1",".bat",".cmd",".vbs",".jse",".wsf",".hta",".sh",".rb",".php",".gd"};
    private static readonly Regex HostPattern=new(@"https?://(?:[a-z0-9._~!$&'()*+,;=:%-]{1,256}@)?(?<host>\[[0-9a-f:]+\]|[a-z0-9.-]{1,253})(?=[:/\s?#\x00'""<>]|$)",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,TimeSpan.FromSeconds(2));
    public static List<string> Hosts(byte[] bytes,CancellationToken ct=default)
    {
        var hosts=new HashSet<string>(StringComparer.OrdinalIgnoreCase);const int chunk=256*1024;
        // Scan the full bounded file in overlapping chunks, ASCII and both UTF-16 alignments.
        for(int offset=0;offset<bytes.Length;offset+=chunk){ct.ThrowIfCancellationRequested();int len=Math.Min(chunk+1024,bytes.Length-offset);
            void Read(string s){foreach(Match m in HostPattern.Matches(s)){var h=m.Groups["host"].Value.Trim('[',']').TrimEnd('.').ToLowerInvariant();if(h.Length>0&&Uri.CheckHostName(h)!=UriHostNameType.Unknown)hosts.Add(h);if(hosts.Count>=512)throw new InvalidDataException("域名线索超过分析上限");}}
            Read(Encoding.Latin1.GetString(bytes,offset,len));Read(Encoding.Unicode.GetString(bytes,offset,len&~1));if(len>2)Read(Encoding.Unicode.GetString(bytes,offset+1,(len-1)&~1));
        }return hosts.OrderBy(x=>x,StringComparer.Ordinal).ToList();
    }
    public static bool IsPe(byte[] b)=>b.Length>=2&&b[0]==77&&b[1]==90;
    public static bool IsManaged(byte[] b){using var p=new PEReader(new MemoryStream(b,false));return p.HasMetadata;}
    public static bool IsMixed(byte[] b){using var p=new PEReader(new MemoryStream(b,false));return p.PEHeaders.CorHeader is { } c && (c.Flags & CorFlags.ILOnly)==0;}
    public static Analysis Script(byte[] bytes,string ext,CancellationToken ct)
    {
        if(bytes.Length>8*1024*1024)return new(Risk.Unknown,"脚本",[],"脚本文本超过 8 MiB 分析上限");
        if(bytes.Length==0)return new(Risk.High,"脚本",[new("空脚本/可执行附件",Risk.High,"文件","需复核")]);
        string text;try{if(bytes.AsSpan().StartsWith(new byte[]{255,254}))text=new UnicodeEncoding(false,true,true).GetString(bytes,2,bytes.Length-2);else if(bytes.AsSpan().StartsWith(new byte[]{254,255}))text=new UnicodeEncoding(true,true,true).GetString(bytes,2,bytes.Length-2);else text=new UTF8Encoding(false,true).GetString(bytes);}catch(DecoderFallbackException){return new(Risk.Unknown,"脚本",[],"非 UTF-8/UTF-16 文本，可能是编译脚本或其他编码");}
        if(text.Contains('\0'))return new(Risk.Unknown,"脚本",[],"含 NUL 字节，无法可靠作为文本分析");
        var evidence=new List<Evidence>();var risk=Risk.Clear;var found=new HashSet<string>();
        void Match(string key,string title,string pattern,Risk level){ct.ThrowIfCancellationRequested();var rx=new Regex(pattern,RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,TimeSpan.FromSeconds(2));foreach(Match m in rx.Matches(text)){found.Add(key);if(evidence.Count<100){int line=1;for(int i=0;i<m.Index;i++)if(text[i]=='\n')line++;evidence.Add(new(title,level,$"行 {line}","命中关键字/调用形式；未证明可达性或真实数据流"));}if((int)level>(int)risk)risk=level;break;}}
        Match("network","脚本网络通信",@"\b(?:requests\s*\.|urllib\s*\.|http\s*\.\s*(?:Fetch|Post|request)|https?\s*\.\s*(?:get|request)|socket\s*\.|fetch\s*\(|axios\s*\.|Invoke-WebRequest|Invoke-RestMethod|curl(?:\.exe)?\b|wget\b|XMLHttpRequest|HTTPClient\s*\.)",Risk.Review);
        Match("direct","直接文件下载接口",@"\b(?:urlretrieve|DownloadFile(?:Async)?|download_file)\s*\(|\b(?:curl(?:\.exe)?\s+[^\r\n]{0,180}(?:-o\s|--output\s)|wget\s+[^\r\n]{0,180}-O\s|Invoke-WebRequest\s+[^\r\n]{0,180}-OutFile\b|Start-BitsTransfer\b)",Risk.Review);
        Match("write","脚本文件写入线索",@"\b(?:write_bytes|write_text|writeFile(?:Sync)?|WriteAllBytes|WriteAllText|Set-Content|Out-File|file\s*\.\s*Write|io\s*\.\s*open|open\s*\([^\r\n]{0,180},\s*['"" ](?:wb|ab|w|a))",Risk.Review);
        Match("execute","脚本外部进程/命令执行",@"\b(?:os\s*\.\s*(?:execute|system|popen)|subprocess\s*\.|child_process|Start-Process|ShellExecute|WScript\s*\.\s*Shell|cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-)",Risk.High);
        Match("dynamic","脚本动态代码执行/原生加载",@"\b(?:eval|exec|loadstring|dofile|loadfile|Invoke-Expression|ctypes\s*\.\s*(?:CDLL|WinDLL)|package\s*\.\s*loadlib)\s*(?:\(|\b)",Risk.Review);
        Match("credential","脚本凭据或启动项线索",@"(?:Login Data|loginusers\.vdf|CurrentVersion[\\/]Run|CryptUnprotectData)",Risk.Review);
        Match("encoded","脚本编码/混淆线索",@"\b(?:FromBase64String|b64decode|atob|EncodedCommand)\b",Risk.Review);
        if((found.Contains("network")||found.Contains("direct"))&&(found.Contains("execute")||found.Contains("dynamic"))){risk=Risk.High;evidence.Add(new("联网/下载与执行共现",Risk.High,"脚本级","启发式共现，不代表已下载执行"));}
        return new(risk,"脚本 "+ext,evidence,Download:found.Contains("direct")?"直接文件下载 API":found.Contains("network")&&found.Contains("write")?"疑似下载落盘":found.Contains("network")?"普通联网（未见落盘）":"未发现");
    }
    public static Analysis Native(byte[] bytes,CancellationToken ct)
    {
        using var pe=new PEReader(new MemoryStream(bytes,false));var hdr=pe.PEHeaders.PEHeader??throw new BadImageFormatException("无 PE 头");
        var evidence=new List<Evidence>();var risk=Risk.Review;var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var libs=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        evidence.Add(new("原生 PE 静态分析",Risk.Review,"PE 头",$"{pe.PEHeaders.CoffHeader.Machine}；{hdr.Magic}；{pe.PEHeaders.SectionHeaders.Length} 节；不分析运行时动态解析的所有 API"));
        byte[] Read(int rva,int n){if(rva<=0||n<=0)throw new BadImageFormatException("无效 RVA");var block=pe.GetSectionData(rva);if(block.Length<n)throw new BadImageFormatException("导入表越界");return block.GetContent(0,n).ToArray();}
        string Str(int rva){var block=pe.GetSectionData(rva);var a=block.GetContent(0,Math.Min(block.Length,1024)).ToArray();int end=Array.IndexOf(a,(byte)0);if(end<0)throw new BadImageFormatException("导入名未终止");return Encoding.ASCII.GetString(a,0,end);}
        var dir=hdr.ImportTableDirectory;bool plus=hdr.Magic==PEMagic.PE32Plus;int stride=plus?8:4;
        if(dir.RelativeVirtualAddress!=0){if(dir.Size<20)throw new BadImageFormatException("导入表过短");bool end=false;int count=0;for(int i=0;i<Math.Min(dir.Size/20,2048);i++){ct.ThrowIfCancellationRequested();var d=Read(checked(dir.RelativeVirtualAddress+i*20),20);int thunk=BinaryPrimitives.ReadInt32LittleEndian(d);int name=BinaryPrimitives.ReadInt32LittleEndian(d.AsSpan(12));int first=BinaryPrimitives.ReadInt32LittleEndian(d.AsSpan(16));if(d.All(x=>x==0)){end=true;break;}libs.Add(Str(name));if(thunk==0)thunk=first;bool thunkEnd=false;for(int j=0;j<8192;j++){if(++count>50000)throw new InvalidDataException("导入项超过上限");var t=Read(checked(thunk+j*stride),stride);ulong v=plus?BinaryPrimitives.ReadUInt64LittleEndian(t):BinaryPrimitives.ReadUInt32LittleEndian(t);if(v==0){thunkEnd=true;break;}if((v&(plus?0x8000000000000000UL:0x80000000UL))==0)names.Add(Str(checked((int)v+2)));}if(!thunkEnd)throw new InvalidDataException("导入表未结束");}if(!end)throw new InvalidDataException("导入描述符未结束");}
        bool Has(params string[] api)=>names.Any(n=>api.Any(a=>n.Equals(a,StringComparison.OrdinalIgnoreCase)||n.Equals(a+"A",StringComparison.OrdinalIgnoreCase)||n.Equals(a+"W",StringComparison.OrdinalIgnoreCase)));
        bool direct=Has("URLDownloadToFile","URLDownloadToCacheFile"),network=direct||Has("WinHttpSendRequest","InternetOpenUrl","InternetReadFile","connect","WSAConnect","recv","curl_easy_perform"),write=Has("WriteFile","CreateFile","fwrite"),execute=Has("CreateProcess","ShellExecute","ShellExecuteEx","WinExec"),load=Has("LoadLibrary","LoadLibraryEx","GetProcAddress");
        void Add(string name,Risk r,string info){evidence.Add(new(name,r,"PE 导入表",info));if((int)r>(int)risk)risk=r;}
        if(network)Add("原生网络 API",Risk.Review,"网络导入项");if(direct)Add("原生直接文件下载 API",Risk.Review,"URLDownloadToFile/CacheFile");if(write)Add("原生文件写入",Risk.Review,"文件 API");if(execute)Add("原生外部进程启动",Risk.High,"进程/ Shell API");if(load)Add("原生动态加载",Risk.Review,"动态加载/符号解析 API");
        if(network&&(execute||load))Add("原生联网与执行/加载共现",Risk.High,"导入项共现，未证明调用顺序");if(Has("WriteProcessMemory","CreateRemoteThread","VirtualAllocEx"))Add("跨进程操作能力",Risk.High,"需人工复核");if(Has("CryptUnprotectData"))Add("系统保护数据解密",Risk.High,"需人工复核");
        if(hdr.DelayImportTableDirectory.RelativeVirtualAddress!=0)Add("存在延迟导入",Risk.Review,"当前未解析延迟导入表");
        if(pe.PEHeaders.SectionHeaders.Any(s=>((uint)s.SectionCharacteristics&0xA0000000u)==0xA0000000u))Add("可写且可执行节",Risk.High,"PE 节权限线索");
        evidence.Add(new("导入库摘要",Risk.Review,"PE 导入表",string.Join(", ",libs.OrderBy(x=>x).Take(40))));
        if(names.Count>0)evidence.Add(new("导入函数摘要",Risk.Review,"PE 导入表",string.Join(", ",names.OrderBy(x=>x).Take(120))));
        return new(risk,"原生 PE",evidence,Download:direct?"直接文件下载 API":network&&write?"疑似下载落盘":network?"普通联网（未见落盘）":"未发现");
    }
    public static Analysis AddHosts(Analysis a,byte[] bytes,CancellationToken ct){try{return a with {Hosts=(a.Hosts??[]).Concat(Hosts(bytes,ct)).Distinct(StringComparer.OrdinalIgnoreCase).Take(512).ToList()};}catch(OperationCanceledException){throw;}catch(Exception){return a with {Risk=a.Risk is Risk.High or Risk.Critical?a.Risk:Risk.Unknown,Error=(a.Error??"")+" 域名提取未完成"};}}
    private static bool IsBlocked(string host,HashSet<string> blocked){if(blocked.Contains(host))return true;if(IPAddress.TryParse(host,out _))return false;for(int i=host.IndexOf('.');i>=0;i=host.IndexOf('.',i+1))if(blocked.Contains(host[(i+1)..]))return true;return false;}
    public static Analysis Reputation(Analysis a,HashSet<string> blocked){var ev=new List<Evidence>(a.Evidence);var risk=a.Risk;foreach(var h in a.Hosts??[]){if(IsBlocked(h,blocked)){ev.Add(new("命中本地域名名单",Risk.High,"静态 URL 主机",h));risk=RiskFusion.Merge(risk,Risk.High);}else if(IPAddress.TryParse(h,out _)||h.Contains("xn--",StringComparison.OrdinalIgnoreCase)){ev.Add(new("IP/国际化域名线索",Risk.Review,"静态 URL 主机",h));if(risk==Risk.Clear)risk=Risk.Review;}}return a with{Risk=risk,Evidence=ev};}
}
