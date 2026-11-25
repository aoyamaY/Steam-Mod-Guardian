using Mono.Cecil;
using Mono.Cecil.Cil;
namespace Guardian.Core;
public static class Rules
{
    public const string Version = "2.1.0-r1";
    private const int MaxEvidence = 300;
    private sealed record Hit(string Category, string Method, string Detail, int Token);
    private static IEnumerable<TypeDefinition> Types(IEnumerable<TypeDefinition> types)
    {
        foreach (var t in types) { yield return t; foreach (var n in Types(t.NestedTypes)) yield return n; }
    }
    private static bool Starts(string s, string prefix) => s.StartsWith(prefix, StringComparison.Ordinal);
    private static bool Has(string s, string value) => s.Contains(value, StringComparison.OrdinalIgnoreCase);
    public static Analysis Inspect(byte[] bytes, string extension, CancellationToken ct = default, bool inspectPayloads = true)
    {
        try
        {
            Analysis a;
            if(PayloadInspection.Zip(bytes) && inspectPayloads) a=new(Risk.Clear,"ZIP / JAR 归档",[]);
            else if(DeepInspection.Scripts.Contains(extension)) a=DeepInspection.Script(bytes,extension,ct);
            else if(DeepInspection.IsPe(bytes) && ((extension is ".dll" or ".exe" or ".asi" or ".scr" or ".com" or ".pyd" or ".ocx") || PayloadInspection.BlobExtension(extension)))
            {
                if(DeepInspection.IsManaged(bytes))
                {
                    a=InspectManaged(bytes,".dll",ct);
                    if(DeepInspection.IsMixed(bytes)){var n=DeepInspection.Native(bytes,ct);a=a with {Kind="混合模式 PE",Risk=RiskFusion.Merge(a.Risk,n.Risk),Evidence=a.Evidence.Concat(n.Evidence).ToList(),Download=PayloadInspection.StrongerDownload(a.Download,n.Download)};}
                }
                else a=DeepInspection.Native(bytes,ct);
                if((extension is ".exe" or ".scr" or ".com") && a.Risk!=Risk.Unknown&&(int)a.Risk<(int)Risk.High)a=a with {Risk=Risk.High,Evidence=a.Evidence.Append(new Evidence("模组携带可执行程序",Risk.High,"文件","未执行")).ToList()};
            }
            else if(extension is ".so" or ".dylib" or ".luac" or ".pyc" or ".jar" or ".zip")a=new(Risk.Unknown,"未支持的二进制/归档",[],"暂不解析 ELF、Mach-O、编译脚本或 JAR 内部内容");
            else a=InspectManaged(bytes,extension,ct);
            if(PayloadInspection.BlobExtension(extension)&&DeepInspection.IsPe(bytes))a=a with {Risk=RiskFusion.Merge(a.Risk,Risk.Review),Evidence=a.Evidence.Append(new Evidence("资源扩展名中的 PE 文件",Risk.Review,"文件头","文件扩展名为资源格式，但内容具有 PE 文件头；可能是合法嵌入组件，需核实")).ToList()};
            a=DeepInspection.AddHosts(a,bytes,ct);
            return DownloadRiskPolicy.Apply(inspectPayloads?PayloadInspection.Inspect(a,bytes,extension,ct):a);
        }
        catch(OperationCanceledException){throw;}
        catch(Exception ex){return new(Risk.Unknown,"深度分析未完成",[],ex.GetType().Name+": "+ex.Message);}
    }
    private static Analysis InspectManaged(byte[] bytes, string extension, CancellationToken ct)
    {
        // Never resolve dependencies, load an assembly into the CLR, or invoke its code.
        if (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
            return new(Risk.High, "EXE", [new("模组携带可执行程序", Risk.High, "文件", "需单独核实用途；未执行")]);
        if (!extension.Equals(".dll", StringComparison.OrdinalIgnoreCase))
            return new(Risk.High, "脚本/安装程序", [new("模组携带可执行脚本或安装程序", Risk.High, "文件", "未执行，需人工复核")]);
        try
        {
            using var stream = new MemoryStream(bytes, writable:false);
            using var module = ModuleDefinition.ReadModule(stream, new ReaderParameters { ReadingMode = ReadingMode.Deferred, ReadSymbols = false });
            var hits = new List<Hit>();
            var localTypes=Types(module.Types).ToList();
            var localMethods=localTypes.SelectMany(t=>t.Methods).GroupBy(m=>m.FullName).ToDictionary(g=>g.Key,g=>g.First(),StringComparer.Ordinal);
            var typeMap=localTypes.GroupBy(t=>t.FullName).ToDictionary(g=>g.Key,g=>g.First(),StringComparer.Ordinal);
            var edges = new Dictionary<int, HashSet<int>>();
            var evidence = new List<Evidence>();
            var categories = new HashSet<string>();
            var risk = Risk.Clear;
            void Add(string rule, Risk r, string where, string detail)
            {
                if ((int)r > (int)risk) risk = r;
                if (evidence.Any(e => e.Rule == rule && e.Method == where && e.Detail == detail)) return;
                if (evidence.Count < MaxEvidence) evidence.Add(new(rule,r,where,detail));
                else { int idx = evidence.FindIndex(e => (int)e.Risk < (int)r); if (idx >= 0) evidence[idx] = new(rule,r,where,detail); }
            }
            void Mark(string category, string method, string detail, int token)
            {
                categories.Add(category);
                if (hits.Count < 100_000) hits.Add(new(category, method, detail, token));
                else throw new InvalidDataException("行为记录超过安全分析上限");
            }
            var fingerprints = new HashSet<string>();
            int instructions = 0; int flowBudget=0; bool flowLimited=false, flowDisk=false; var restoredHosts=new HashSet<string>(StringComparer.OrdinalIgnoreCase); var fuzzy=new HashSet<string>();
            foreach(var t in localTypes)
            foreach(var m in t.Methods)
            {
                ct.ThrowIfCancellationRequested();
                int token = m.MetadataToken.ToInt32();
                string where = m.FullName;
                // Link compiler-generated async/iterator state machine MoveNext using local metadata only.
                foreach(var attr in m.CustomAttributes.Where(a=>a.AttributeType.FullName is "System.Runtime.CompilerServices.AsyncStateMachineAttribute" or "System.Runtime.CompilerServices.IteratorStateMachineAttribute" or "System.Runtime.CompilerServices.AsyncIteratorStateMachineAttribute"))
                    if(attr.ConstructorArguments.Count==1 && attr.ConstructorArguments[0].Value is TypeReference state && typeMap.TryGetValue(state.FullName,out var st))
                        foreach(var move in st.Methods.Where(x=>x.Name=="MoveNext")){if(!edges.TryGetValue(token,out var link))edges[token]=link=[];link.Add(move.MetadataToken.ToInt32());}
                if (m.IsPInvokeImpl) { Add("P/Invoke 原生调用",Risk.Review,where,m.PInvokeInfo?.Module?.Name ?? "未知模块"); Mark("native",where,"P/Invoke",token); }
                if (!m.HasBody) continue;
                int hitStart=hits.Count;
                foreach(var i in m.Body.Instructions)
                {
                    if (++instructions > 3_000_000) throw new InvalidDataException("IL 指令超过分析上限");
                    if ((instructions & 4095) == 0) ct.ThrowIfCancellationRequested();
                    string loc = $"IL_{i.Offset:X4}";
                    if (i.OpCode.Code == Code.Ldstr && i.Operand is string s)
                    {
                        // String hints are not proof of file access. Avoid disclosing arbitrary strings/secrets in reports.
                        if (Has(s,"Login Data") || Has(s,"Local State") || Has(s,"leveldb") || Has(s,"\\Cookies") || Has(s,"/Cookies") || Has(s,"ssfn"))
                        { Mark("credentialHint",where,loc,token); Add("凭据相关字符串线索",Risk.Review,where,loc+"（内容省略）"); }
                        if (Has(s,"CurrentVersion\\Run") || Has(s,"CurrentVersion/Run") || Has(s,"Startup\\"))
                        { Mark("persistHint",where,loc,token); Add("启动项路径线索",Risk.Review,where,loc+"（内容省略）"); }
                        if (Has(s,"steam.exe") || Has(s,"steamclient.dll") || Has(s,"steamui.dll") || Has(s,"loginusers.vdf"))
                        { Mark("steamHint",where,loc,token); Add("Steam 客户端文件名线索",Risk.Review,where,loc+"（内容省略）"); }
                        if (Has(s,"powershell") || Has(s,"cmd.exe") || Has(s,"wscript") || Has(s,"mshta"))
                        { Mark("shellHint",where,loc,token); Add("系统命令解释器字符串",Risk.Review,where,loc+"（内容省略）"); }
                    }
                    if (i.Operand is not MethodReference target) continue;
                    if (i.OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj or Code.Ldftn or Code.Ldvirtftn or Code.Jmp)) continue;
                    string type = target.DeclaringType.FullName, name = target.Name, detail = loc+" "+type+"::"+name;
                    // Only link local methods. Never Resolve() an untrusted external reference.
                    var md=target as MethodDefinition;
                    if(md==null && target.DeclaringType.Scope==module)localMethods.TryGetValue(target.FullName,out md);
                    if(md!=null && md.Module==module)
                    { if (!edges.TryGetValue(token,out var next)) edges[token] = next = []; next.Add(md.MetadataToken.ToInt32()); }
                    void H(string category, string rule, Risk r) { Mark(category,where,detail,token); Add(rule,r,where,detail); }
                    if ((Starts(type,"System.Net.Http.") && (name.StartsWith("Get") || name.StartsWith("Post") || name.StartsWith("Send") || name.StartsWith("Put"))) ||
                        (type == "System.Net.WebClient" && (name.StartsWith("Download") || name.StartsWith("Upload") || name.StartsWith("OpenRead"))) ||
                        (Starts(type,"System.Net.") && (name == "GetResponse" || name == "GetResponseAsync" || name == "Connect" || name == "ConnectAsync")) ||
                        (Starts(type,"UnityEngine.Networking.UnityWebRequest") && (name == "SendWebRequest" || name == "Send")))
                    { H("network","网络通信",Risk.Review); }
                    if ((type == "System.Net.WebClient" && name.StartsWith("DownloadFile")) || (type == "UnityEngine.Networking.DownloadHandlerFile" && name == ".ctor"))
                    { H("downloadFile","直接文件下载 API",Risk.Review); Mark("network",where,detail,token); Mark("write",where,detail,token); }
                    if ((type == "System.Net.WebClient" && (name.StartsWith("DownloadData") || name.StartsWith("OpenRead"))) || (type == "System.Net.Http.HttpClient" && (name.StartsWith("GetByteArray") || name.StartsWith("GetStream"))) || (type == "System.Net.Http.HttpContent" && (name.StartsWith("ReadAsByteArray") || name.StartsWith("ReadAsStream") || name.StartsWith("CopyTo"))))
                    { H("downloadBytes","网络数据/流接收 API",Risk.Review); }
                    if ((type == "System.IO.Stream" && name.StartsWith("CopyTo")) || (type == "System.IO.BinaryWriter" && name == "Write")) Mark("write",where,detail,token);
                    if ((type == "System.Diagnostics.Process" && name == "Start") || (type == "System.Diagnostics.ProcessStartInfo" && name == ".ctor"))
                    { H(name == "Start" ? "execute" : "processSetup", "外部进程相关调用", name == "Start" ? Risk.High : Risk.Review); }
                    if ((type == "System.Reflection.Assembly" && (name == "Load" || name == "LoadFrom" || name == "LoadFile" || name == "UnsafeLoadFrom")) ||
                        (type == "System.AppDomain" && (name == "Load" || name == "ExecuteAssembly" || name == "ExecuteAssemblyByName")) ||
                        (type == "System.Runtime.Loader.AssemblyLoadContext" && name.StartsWith("Load")))
                    { H("load","动态程序集加载",Risk.High); }
                    if ((type == "System.IO.File" && (name.StartsWith("Write") || name.StartsWith("Append") || name is "Create" or "Copy" or "Move" or "Replace" or "Delete" or "OpenWrite")) ||
                        (type == "System.IO.FileStream" && (name == ".ctor" || name.StartsWith("Write"))) ||
                        (type == "System.IO.Directory" && name is "Delete" or "Move") ||
                        (type == "System.Net.WebClient" && name.StartsWith("DownloadFile")) ||
                        (Starts(type,"System.IO.Compression.") && name.StartsWith("ExtractTo"))) Mark("write",where,detail,token);
                    if ((type == "System.IO.File" && (name.StartsWith("Read") || name.StartsWith("Open"))) || type == "System.IO.FileStream" || type == "System.IO.StreamReader") Mark("read",where,detail,token);
                    if (Starts(type,"Microsoft.Win32.Registry") && (name.StartsWith("SetValue") || name.StartsWith("CreateSubKey") || name.StartsWith("Delete"))) H("registry","注册表修改",Risk.High);
                    if (type == "System.Security.Cryptography.ProtectedData" && name == "Unprotect") H("decrypt","系统保护数据解密",Risk.High);
                    if (type == "System.Runtime.InteropServices.NativeLibrary" && (name == "Load" || name == "TryLoad")) H("nativeLoad","动态原生库加载",Risk.High);
                    if ((type == "System.Reflection.MethodBase" || type == "System.Reflection.MethodInfo" || type == "System.Delegate") && (name == "Invoke" || name == "DynamicInvoke")) Mark("reflection",where,detail,token);
                }
                if(flowBudget<200000)
                {
                    flowBudget+=m.Body.Instructions.Count;
                    var flow=LocalFlow.Inspect(m,ct);flowLimited|=flow.Limited;flowDisk|=flow.Disk;
                    foreach(var e in flow.Evidence)Add(e.Rule,e.Risk,e.Method,e.Detail);
                    foreach(var host in flow.Hosts)if(restoredHosts.Count<256)restoredHosts.Add(host);
                }
                else flowLimited=true;
                if(hits.Skip(hitStart).Any(h=>h.Category is "network" or "downloadFile" or "downloadBytes" or "execute" or "load" or "nativeLoad" or "registry" or "decrypt"))
                {
                    if(fingerprints.Count<4096 && m.Body.Instructions.Count>=8)
                    {
                        var normalized=new System.Text.StringBuilder();
                        foreach(var ins in m.Body.Instructions)
                        {
                            normalized.Append(ins.OpCode.Code).Append(':');
                            if(ins.Operand is MethodReference mr)
                            {
                                string scope=mr.DeclaringType.Scope?.Name??"";
                                if(scope.StartsWith("System",StringComparison.Ordinal)||scope.StartsWith("UnityEngine",StringComparison.Ordinal)||scope is "mscorlib" or "netstandard") normalized.Append(mr.DeclaringType.FullName).Append("::").Append(mr.Name);
                                else normalized.Append("local_or_other_call");
                            }
                            normalized.Append(';');
                        }
                        if(fuzzy.Count<256 && m.Body.Instructions.Count>=16)fuzzy.Add(IlSimilarity.Fingerprint(normalized.ToString()));
                        fingerprints.Add(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(normalized.ToString()))));
                    }
                }
            }
            // Same-method and local-call relationships are correlation, not data-flow proof.
            void Pair(string a, string b, string label, Risk severity)
            {
                if (!categories.Contains(a) || !categories.Contains(b)) return;
                var left=hits.Where(h=>h.Category==a).GroupBy(h=>h.Token).Select(g=>g.First()).ToList();
                var right=hits.Where(h=>h.Category==b).GroupBy(h=>h.Token).ToDictionary(g=>g.Key,g=>g.First());
                var reverse=new Dictionary<int,List<int>>();
                foreach(var (from, toSet) in edges) foreach(int to in toSet) { if(!reverse.TryGetValue(to,out var list)) reverse[to]=list=[]; list.Add(from); }
                foreach(var l in left.Take(500))
                {
                    ct.ThrowIfCancellationRequested();
                    var seen=new HashSet<int>{l.Token}; var q=new Queue<(int,int)>(); q.Enqueue((l.Token,0));
                    while(q.Count>0 && seen.Count<=3000)
                    {
                        var (v,d)=q.Dequeue();
                        if(right.TryGetValue(v,out var r)) { Add(label,severity,l.Method,$"{l.Detail} ↔ {r.Method}: {r.Detail}（同方法/有限本地调用关系，不证明数据流）"); return; }
                        if(d>=4) continue;
                        if(edges.TryGetValue(v,out var next)) foreach(int n in next) if(seen.Add(n)) q.Enqueue((n,d+1));
                        if(reverse.TryGetValue(v,out var prev)) foreach(int n in prev) if(seen.Add(n)) q.Enqueue((n,d+1));
                    }
                }
                var first=left[0]; var other=right.Values.First();
                Add(label+"（程序集级共现）", severity == Risk.Critical ? Risk.High : Risk.Review, first.Method,$"{first.Detail}；{other.Method}: {other.Detail}（未确认调用关系）");
            }
            Pair("network","execute","联网 + 外部进程启动（疑似下载执行）",Risk.Critical);
            Pair("network","load","联网 + 动态程序集加载（疑似下载加载）",Risk.Critical);
            Pair("network","nativeLoad","联网 + 动态原生库加载",Risk.Critical);
            Pair("network","write","联网 + 文件写入",Risk.Review);
            Pair("downloadBytes","write","接收网络数据 + 文件写入（疑似下载落盘）",Risk.Review);
            Pair("steamHint","write","Steam 文件名线索 + 写入",Risk.High);
            Pair("credentialHint","read","凭据线索 + 文件读取",Risk.High);
            Pair("credentialHint","decrypt","凭据线索 + 系统数据解密",Risk.Critical);
            Pair("persistHint","registry","启动项线索 + 注册表修改",Risk.Critical);
            Pair("shellHint","execute","命令解释器线索 + 外部进程启动",Risk.Critical);
            // Evidence cap prioritizes higher-severity reasons.
            if(flowLimited)Add("有限数据流分析覆盖受限",Risk.Review,"静态分析","方法大小、异常处理、栈或预算限制；不代表安全，也不影响原有启发式规则。");
            var download=categories.Contains("downloadFile")?"直接文件下载 API":(flowDisk||categories.Contains("downloadBytes")&&categories.Contains("write"))?"疑似下载落盘":categories.Contains("network")&&categories.Contains("write")?"联网+写入（待核实）":categories.Contains("downloadBytes")?"接收数据/流（未见落盘）":categories.Contains("network")?"普通联网（未见落盘）":"未发现";
            return new(risk,"托管 DLL",evidence.OrderByDescending(e=>e.Risk).ToList(),Fingerprints:fingerprints.ToList(),Download:download,Hosts:restoredHosts.ToList(),FuzzyFingerprints:fuzzy.ToList());
        }
        catch(OperationCanceledException) { throw; }
        catch(BadImageFormatException) { return new(Risk.Unknown,"原生/无效 DLL",[new("无法进行托管 IL 分析",Risk.Unknown,"文件","可能是原生 DLL、混合模式或损坏文件")],"无法解析为托管 DLL，需人工复核"); }
        catch(Exception ex) { return new(Risk.Unknown,"分析失败",[],ex.GetType().Name+": "+ex.Message); }
    }
}
