using Guardian.Core;
using Mono.Cecil;
using Mono.Cecil.Cil;
// Inert, in-memory metadata fixtures only. No emitted method is loaded or executed.
static byte[] Fixture(bool network, bool process, bool separate=false)
{
    using var module=ModuleDefinition.CreateModule("GuardianFixture",ModuleKind.Dll);
    var t=new TypeDefinition("Fixture","Sample",TypeAttributes.Public|TypeAttributes.Class,module.TypeSystem.Object);module.Types.Add(t);
    MethodDefinition Create(string name){var m=new MethodDefinition(name,MethodAttributes.Public|MethodAttributes.Static,module.TypeSystem.Void);t.Methods.Add(m);return m;}
    var m=Create("SampleMethod");
    void AddReference(MethodDefinition owner,string ns,string type,string method)
    {
        // ldftn + pop records a reference without actually calling anything.
        var reference=new MethodReference(method,module.TypeSystem.Void,new TypeReference(ns,type,module,module.TypeSystem.CoreLibrary));
        var il=owner.Body.GetILProcessor();il.Emit(OpCodes.Ldftn,reference);il.Emit(OpCodes.Pop);
    }
    if(network)AddReference(m,"System.Net","WebClient","DownloadData");
    if(process){var p=separate?Create("Independent"):m;AddReference(p,"System.Diagnostics","Process","Start");if(separate)p.Body.GetILProcessor().Emit(OpCodes.Ret);}
    m.Body.GetILProcessor().Emit(OpCodes.Ret);using var ms=new MemoryStream();module.Write(ms);return ms.ToArray();
}
static void Check(string name,Risk actual,Risk expected){if(actual!=expected)throw new Exception($"{name}: expected {expected}, got {actual}");Console.WriteLine($"PASS {name}");}
Check("ordinary",Rules.Inspect(Fixture(false,false),".dll").Risk,Risk.Clear);
Check("network only",Rules.Inspect(Fixture(true,false),".dll").Risk,Risk.Review);
Check("correlated calls",Rules.Inspect(Fixture(true,true),".dll").Risk,Risk.Critical);
Check("uncorrelated calls",Rules.Inspect(Fixture(true,true,true),".dll").Risk,Risk.High);
Check("unparseable DLL",Rules.Inspect([1,2,3],".dll").Risk,Risk.Unknown);
Check("script",Rules.Inspect([],".ps1").Risk,Risk.High);
// Inert IL metadata fixtures for download detection; references only, no calls.
static byte[] DownloadFixture(string api,bool write)
{
    using var module=ModuleDefinition.CreateModule("DownloadFixture",ModuleKind.Dll);
    var t=new TypeDefinition("Fixture","Sample",TypeAttributes.Public|TypeAttributes.Class,module.TypeSystem.Object);module.Types.Add(t);
    var m=new MethodDefinition("Sample",MethodAttributes.Public|MethodAttributes.Static,module.TypeSystem.Void);t.Methods.Add(m);
    var il=m.Body.GetILProcessor();
    void Reference(string ns,string type,string method){il.Emit(OpCodes.Ldftn,new MethodReference(method,module.TypeSystem.Void,new TypeReference(ns,type,module,module.TypeSystem.CoreLibrary)));il.Emit(OpCodes.Pop);}
    Reference("System.Net","WebClient",api);if(write)Reference("System.IO","File","WriteAllBytes");
    for(int i=0;i<8;i++)il.Emit(OpCodes.Nop);il.Emit(OpCodes.Ret);
    using var ms=new MemoryStream();module.Write(ms);return ms.ToArray();
}
static void Equal(string name,string actual,string expected){if(actual!=expected)throw new Exception($"{name}: expected {expected}, got {actual}");Console.WriteLine("PASS "+name);}
Equal("direct download",Rules.Inspect(DownloadFixture("DownloadFileAsync",false),".dll").Download,"直接文件下载 API");
Equal("download to disk candidate",Rules.Inspect(DownloadFixture("DownloadData",true),".dll").Download,"疑似下载落盘");
Equal("download bytes only",Rules.Inspect(DownloadFixture("DownloadData",false),".dll").Download,"接收数据/流（未见落盘）");
var a=Rules.Inspect(DownloadFixture("DownloadFileAsync",false),".dll");
if(a.Fingerprints==null||a.Fingerprints.Count==0)throw new Exception("missing normalized fingerprint");
Equal("normalized fingerprint stable",a.Fingerprints[0],Rules.Inspect(DownloadFixture("DownloadFileAsync",false),".dll").Fingerprints![0]);
var dir=Path.Combine(Path.GetTempPath(),"guardian-test-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(dir);
try{File.WriteAllText(Path.Combine(dir,"info.ini"),"name=Example\ndisplayName=示例模组");Equal("local mod title",WorkshopNames.LocalName(Path.Combine(dir,"Example.dll"),dir,"fallback"),"示例模组");}finally{Directory.Delete(dir,true);}
using(var rsa=System.Security.Cryptography.RSA.Create(2048))
{
    var feed=new CommunityFeed(1,DateTimeOffset.UtcNow.AddDays(1),[new("il-v1",a.Fingerprints[0],"inert test")]);
    var payload=System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(feed);
    var sig=rsa.SignData(payload,System.Security.Cryptography.HashAlgorithmName.SHA256,System.Security.Cryptography.RSASignaturePadding.Pkcs1);
    var envelope=System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new{Payload=Convert.ToBase64String(payload),Signature=Convert.ToBase64String(sig)});
    var verified=Community.Verify(envelope,rsa.ExportSubjectPublicKeyInfoPem());
    Check("signed fingerprint match",Community.Apply(a with {Risk=Risk.Review},verified,"","").Risk,Risk.High);
    sig[0]^=1;var invalid=System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new{Payload=Convert.ToBase64String(payload),Signature=Convert.ToBase64String(sig)});
    bool rejected=false;try{Community.Verify(invalid,rsa.ExportSubjectPublicKeyInfoPem());}catch(System.Security.Cryptography.CryptographicException){rejected=true;}if(!rejected)throw new Exception("invalid signature accepted");Console.WriteLine("PASS tampered signature rejected");
}
// Temporary directories and inert text only. No real Steam files touched.
var temp=Path.Combine(Path.GetTempPath(),"guardian-v14-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(temp);
try
{
    var lib1=Path.Combine(temp,"library1");var lib2=Path.Combine(temp,"library2");
    var apps1=Path.Combine(lib1,"steamapps");var apps2=Path.Combine(lib2,"steamapps");
    var mods=Path.Combine(apps1,"workshop","content","123","456");Directory.CreateDirectory(mods);
    Directory.CreateDirectory(Path.Combine(apps1,"common","Example"));
    Directory.CreateDirectory(Path.Combine(apps2,"workshop","content","789","111"));
    File.WriteAllText(Path.Combine(apps1,"appmanifest_123.acf"),"\"AppState\" { \"appid\" \"123\" \"name\" \"Example Game\" \"installdir\" \"Example\" }");
    var games=SteamCatalog.Discover([lib1,lib2]);if(games.Count!=2||!games.Single(g=>g.AppId=="123").Installed||games.Single(g=>g.AppId=="789").Installed)throw new Exception("Steam catalog discovery failed");
    Equal("game name from manifest",games.Single(g=>g.AppId=="123").Name,"Example Game");
    Equal("generic workshop app ID",SteamCatalog.WorkshopIdentity(Path.Combine(mods,"sample.dll")).AppId,"123");
    Equal("generic workshop item ID",SteamCatalog.WorkshopIdentity(Path.Combine(mods,"sample.dll")).WorkshopId,"456");
    var path=Path.Combine(mods,"inert.txt");File.WriteAllText(path,"INERT TEST DATA");
    var hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)));
    var row=new ScanRow("Example","456",path,hash,new FileInfo(path).Length,new Analysis(Risk.High,"fixture",[]),false){AppId="123",GameName="Example Game"};
    var vault=Path.Combine(temp,"vault");
    static void Reject(string name,Action a){try{a();}catch(IOException){Console.WriteLine("PASS "+name);return;}throw new Exception(name+": unexpected success");}
    Reject("quarantine rejects clear",()=>Quarantine.Move(row with {Analysis=new Analysis(Risk.Clear,"fixture",[])},[mods],vault));
    Reject("quarantine rejects stale hash",()=>Quarantine.Move(row with {Sha256=new string('0',64)},[mods],vault));
    Reject("quarantine rejects outside root",()=>Quarantine.Move(row,[apps2],vault));
    var entry=Quarantine.Move(row,[mods],vault);if(File.Exists(path)||Quarantine.List(vault).Single()!=entry)throw new Exception("quarantine failed");Console.WriteLine("PASS quarantine move and journal");
    File.WriteAllText(path,"REPLACEMENT");Reject("restore never overwrites",()=>Quarantine.Restore(entry,vault));File.Delete(path);
    Quarantine.Restore(entry,vault);Equal("restore content",File.ReadAllText(path),"INERT TEST DATA");if(Quarantine.List(vault).Count!=0)throw new Exception("restored entry still active");
    var report=new ScanReport(DateTimeOffset.Now,Rules.Version,[mods],[row],[]);
    if(!LaunchChecks.SameFiles(report,report)||LaunchChecks.SameFiles(report,report with {Files=[row with {Sha256=new string('0',64)}]})||LaunchChecks.SameFiles(report,report with {Files=[]}))throw new Exception("launch identity verification failed");Console.WriteLine("PASS launch snapshot checks");
}finally{Directory.Delete(temp,true);}
// v2: inert strings and synthetic metadata, never execute scripts or PE files.
static byte[] Text(string s)=>System.Text.Encoding.UTF8.GetBytes(s);
Check("ordinary Lua",Rules.Inspect(Text("local value = 1"),".lua").Risk,Risk.Clear);
var script=Rules.Inspect(Text("# inert test: urlretrieve(\"https://example.invalid/sample\", \"data.txt\")"),".py");
Equal("script download keyword",script.Download,"直接文件下载 API");
Check("script download evidence",script.Risk,Risk.Critical);
Equal("host privacy",string.Join(",",DeepInspection.Hosts(Text("https://example.invalid/private?token=secret"))),"example.invalid");
Equal("UTF16 host",string.Join(",",DeepInspection.Hosts(System.Text.Encoding.Unicode.GetBytes("https://sample.invalid/data"))),"sample.invalid");
Check("local domain reputation",DeepInspection.Reputation(script with {Risk=Risk.Review},new HashSet<string>(StringComparer.OrdinalIgnoreCase){"example.invalid"}).Risk,Risk.High);
Check("local domain never lowers download risk",DeepInspection.Reputation(script,new HashSet<string>(StringComparer.OrdinalIgnoreCase){"example.invalid"}).Risk,Risk.Critical);
Check("compiled script unknown",Rules.Inspect([1,2,3],".luac").Risk,Risk.Unknown);
Check("bad PE unknown",Rules.Inspect([77,90,0,0],".dll").Risk,Risk.Unknown);
// Synthetic PE32 with one inert section and no CLR or import directory.
static byte[] EmptyPe()
{
    var b=new byte[1024];void U16(int p,ushort v)=>System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(p,2),v);void U32(int p,uint v)=>System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(p,4),v);
    U16(0,0x5A4D);U32(0x3C,0x80);U32(0x80,0x4550);U16(0x84,0x14C);U16(0x86,1);U16(0x94,224);U16(0x96,0x2102);
    int o=0x98;U16(o,0x10B);U32(o+20,0x1000);U32(o+28,0x400000);U32(o+32,0x1000);U32(o+36,0x200);U16(o+40,6);U16(o+48,6);U32(o+56,0x2000);U32(o+60,0x200);U16(o+68,3);U32(o+72,0x100000);U32(o+76,0x1000);U32(o+80,0x100000);U32(o+84,0x1000);U32(o+92,16);
    int h=o+224;System.Text.Encoding.ASCII.GetBytes(".data").CopyTo(b,h);U32(h+8,0x200);U32(h+12,0x1000);U32(h+16,0x200);U32(h+20,0x200);U32(h+36,0x40000040);return b;
}
var native=Rules.Inspect(EmptyPe(),".dll");Equal("native PE kind",native.Kind,"原生 PE");Check("native PE review",native.Risk,Risk.Review);
var profileGames=new[]{new SteamGame("123","A",["rootA"],true),new SteamGame("456","B",["rootB"],true)};
var profileExtra=new Dictionary<string,List<string>>{{"123",["extraA"]},{"456",["extraB"]}};
Equal("per game roots",string.Join(",",ProfileStore.RootsFor(profileGames.Take(1),profileExtra,["global"])),"rootA,extraA,global");
if(ProfileStore.ScopeFile("a")==ProfileStore.ScopeFile("b"))throw new Exception("baseline scope collision");Console.WriteLine("PASS separate baseline scopes");
// v2.0.3: classification only; no actual AMSI submission or sample execution.
var clear203=new Analysis(Risk.Clear,"fixture",[]);
Check("AMSI malware result",AmsiEngine.Classify(clear203,32768).Risk,Risk.Critical);
Check("AMSI policy block",AmsiEngine.Classify(clear203,16384).Risk,Risk.High);
Check("AMSI negative never clears evidence",AmsiEngine.Classify(clear203 with {Risk=Risk.High},1).Risk,Risk.High);
Check("AMSI unknown not safety",AmsiEngine.Classify(clear203 with {Risk=Risk.Unknown},0).Risk,Risk.Unknown);
Check("strong evidence survives incomplete",RiskFusion.Merge(Risk.Critical,Risk.Unknown),Risk.Critical);
static byte[] ZipFixture203(string name,byte[] content)
{
    using var ms=new MemoryStream();using(var zip=new System.IO.Compression.ZipArchive(ms,System.IO.Compression.ZipArchiveMode.Create,true)){using var entry=zip.CreateEntry(name).Open();entry.Write(content);}return ms.ToArray();
}
var packed203=Rules.Inspect(ZipFixture203("assets/data.bin",Fixture(true,true)),".zip");
Check("ZIP disguised managed payload",packed203.Risk,Risk.Critical);
if(!packed203.Evidence.Any(e=>e.Rule=="内部可执行内容"))throw new Exception("ZIP evidence missing");
Check("ZIP nested coverage unknown",Rules.Inspect(ZipFixture203("nested.zip",ZipFixture203("a.txt",Text("inert"))),".zip").Risk,Risk.Unknown);
Check("JAR bytecode coverage unknown",Rules.Inspect(ZipFixture203("sample.class",[1,2,3]),".jar").Risk,Risk.Unknown);
static byte[] ResourceFixture203(byte[] child)
{
    using var m=ModuleDefinition.CreateModule("ResourceFixture",ModuleKind.Dll);
    m.Resources.Add(new EmbeddedResource("payload.bin",ManifestResourceAttributes.Private,child));using var ms=new MemoryStream();m.Write(ms);return ms.ToArray();
}
Check("embedded managed payload",Rules.Inspect(ResourceFixture203(Fixture(true,true)),".dll").Risk,Risk.Critical);
Check("PE disguised as resource",Rules.Inspect(EmptyPe(),".bin").Risk,Risk.Review);
if(!AmsiEngine.ExplainInitializationError(unchecked((int)0x80070103u)).Contains("ERROR_NO_MORE_ITEMS"))throw new Exception("AMSI diagnostic mapping");
Console.WriteLine("PASS payload and engine fusion tests (no provider invoked)");
// v2.0.5: local inert fixtures; no download, subprocess or actual engine invoked.
Check("direct DLL download critical",Rules.Inspect(DownloadFixture("DownloadFileAsync",false),".dll").Risk,Risk.Critical);
Check("suspected DLL download critical",Rules.Inspect(DownloadFixture("DownloadData",true),".dll").Risk,Risk.Critical);
Check("memory-only download review",Rules.Inspect(DownloadFixture("DownloadData",false),".dll").Risk,Risk.Review);
Check("network and write alone not critical",DownloadRiskPolicy.Apply(new Analysis(Risk.Review,"fixture",[],Download:"联网+写入（待核实）")).Risk,Risk.Review);
Check("native download policy",DownloadRiskPolicy.Apply(new Analysis(Risk.Review,"原生 PE",[],Download:"直接文件下载 API")).Risk,Risk.Critical);
Check("archive download critical",Rules.Inspect(ZipFixture203("sample.dll",DownloadFixture("DownloadFileAsync",false)),".zip").Risk,Risk.Critical);
Check("embedded download critical",Rules.Inspect(ResourceFixture203(DownloadFixture("DownloadFileAsync",false)),".dll").Risk,Risk.Critical);
var policy=DownloadRiskPolicy.Apply(a);if(policy.Evidence.Count!=a.Evidence.Count)throw new Exception("duplicate risk evidence");
var inertZip=ZipFixture203("bin/yara64.exe",Text("inert fixture, not an executable"));
var digest205=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(inertZip));
byte[] Meta205(string digest,string url)=>System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new {draft=false,prerelease=false,tag_name="v4.5.5",assets=new[]{new{name="yara-4.5.5-2368-win64.zip",state="uploaded",size=inertZip.Length,digest,browser_download_url=url}}});
const string official205="https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip";
var asset205=YaraInstaller.SelectAsset(Meta205("sha256:"+digest205,official205));YaraInstaller.VerifyPackage(inertZip,asset205);
void Reject205(string name,Action action){try{action();}catch(InvalidDataException){Console.WriteLine("PASS "+name);return;}throw new Exception(name+": unexpected success");}
Reject205("reject invalid package hash",()=>YaraInstaller.VerifyPackage(inertZip,asset205 with {Sha256=new string('0',64)}));
Reject205("reject missing package digest",()=>YaraInstaller.SelectAsset(Meta205("",official205)));
Reject205("reject untrusted download",()=>YaraInstaller.SelectAsset(Meta205("sha256:"+digest205,"https://example.invalid/yara-4.5.5-2368-win64.zip")));
var extract205=Path.Combine(Path.GetTempPath(),"guardian-yara-fixture-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(extract205);
try{var path205=YaraInstaller.ExtractEngine(inertZip,extract205);Equal("extract official named engine",Path.GetFileName(path205),"yara64.exe");Reject205("reject archive traversal",()=>YaraInstaller.ExtractEngine(ZipFixture203("../yara64.exe",Text("inert")),extract205));}finally{Directory.Delete(extract205,true);}
Console.WriteLine("PASS YARA package validation fixtures (no network or engine execution)");
var localized207=new SteamGame("123","Original",[],true,"InstallFolder","中文标题");
Equal("localized display name",localized207.DisplayName,"中文标题 / Original");
Equal("directory is not translation",(localized207 with {LocalizedName=""}).DisplayName,"Original");
// Metadata-only source/sink fixture: no method is executed.
using(var mod210=ModuleDefinition.CreateModule("FlowFixture",ModuleKind.Dll))
{
    var t210=new TypeDefinition("Fixture","Flow",TypeAttributes.Public|TypeAttributes.Class,mod210.TypeSystem.Object);mod210.Types.Add(t210);
    MethodDefinition CreateFlow(bool tainted){var m=new MethodDefinition(tainted?"Related":"Unrelated",MethodAttributes.Public|MethodAttributes.Static,mod210.TypeSystem.Void);t210.Methods.Add(m);var il=m.Body.GetILProcessor();var arr=new ArrayType(mod210.TypeSystem.Byte);var local=new VariableDefinition(arr);m.Body.Variables.Add(local);
        var src=new MethodReference("DownloadData",arr,new TypeReference("System.Net","WebClient",mod210,mod210.TypeSystem.CoreLibrary)){HasThis=true};src.Parameters.Add(new ParameterDefinition(mod210.TypeSystem.String));
        var sink=new MethodReference("WriteAllBytes",mod210.TypeSystem.Void,new TypeReference("System.IO","File",mod210,mod210.TypeSystem.CoreLibrary));sink.Parameters.Add(new ParameterDefinition(mod210.TypeSystem.String));sink.Parameters.Add(new ParameterDefinition(arr));
        il.Emit(OpCodes.Ldnull);il.Emit(OpCodes.Ldstr,"https://example.invalid/");il.Emit(OpCodes.Callvirt,src);il.Emit(OpCodes.Stloc,local);il.Emit(OpCodes.Ldstr,"inert.bin");if(tainted)il.Emit(OpCodes.Ldloc,local);else il.Emit(OpCodes.Ldnull);il.Emit(OpCodes.Call,sink);il.Emit(OpCodes.Ret);return m;}
    if(!LocalFlow.Inspect(CreateFlow(true)).Disk||LocalFlow.Inspect(CreateFlow(false)).Disk)throw new Exception("flow source/sink regression");
    var constMethod=new MethodDefinition("Constants",MethodAttributes.Public|MethodAttributes.Static,mod210.TypeSystem.Void);t210.Methods.Add(constMethod);var cil=constMethod.Body.GetILProcessor();var concat=new MethodReference("Concat",mod210.TypeSystem.String,mod210.TypeSystem.String);concat.Parameters.Add(new ParameterDefinition(mod210.TypeSystem.String));concat.Parameters.Add(new ParameterDefinition(mod210.TypeSystem.String));cil.Emit(OpCodes.Ldstr,"https://");cil.Emit(OpCodes.Ldstr,"example.invalid/");cil.Emit(OpCodes.Call,concat);cil.Emit(OpCodes.Pop);cil.Emit(OpCodes.Ret);if(!LocalFlow.Inspect(constMethod).Hosts.Contains("example.invalid"))throw new Exception("constant recovery");
    Console.WriteLine("PASS bounded flow and constant recovery");
}
Equal("YARA-X NDJSON",string.Join(",",LocalTools.YaraXMatches("{\"path\":\"inert\",\"rules\":[{\"identifier\":\"Guardian_Test\"}]}")),"Guardian_Test");
if(IlSimilarity.Distance("0000000000000000","0000000000000001")!=1||IlSimilarity.Fingerprint("a;b;c;d;e;f;")!=IlSimilarity.Fingerprint("a;b;c;d;e;f;"))throw new Exception("SimHash regression");Console.WriteLine("PASS SimHash");
Console.WriteLine("All fixture tests passed. No fixture code executed.");
