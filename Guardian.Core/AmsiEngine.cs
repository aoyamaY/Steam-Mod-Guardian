using System.Runtime.InteropServices;
namespace Guardian.Core;
// Explicit opt-in. The registered Windows provider may use cloud protection per its own policy.
public sealed class AmsiEngine : IDisposable
{
    IntPtr context; string? error;
    public bool IsAvailable => context!=IntPtr.Zero && error==null;
    public string? InitializationError => error;
    public static string ExplainInitializationError(int hr) => hr==unchecked((int)0x80070103u)
        ? "初始化失败 0x80070103（ERROR_NO_MORE_ITEMS；AMSI 无可用数据，请检查系统安全提供程序状态）"
        : $"初始化失败 0x{hr:X8}";
    [DllImport("amsi.dll",CharSet=CharSet.Unicode)] static extern int AmsiInitialize(string appName,out IntPtr context);
    [DllImport("amsi.dll",CharSet=CharSet.Unicode)] static extern int AmsiScanBuffer(IntPtr context,byte[] buffer,uint length,string contentName,IntPtr session,out int result);
    [DllImport("amsi.dll")] static extern void AmsiUninitialize(IntPtr context);
    public AmsiEngine(){try{if(!OperatingSystem.IsWindows()){error="仅支持 Windows";return;}int hr=AmsiInitialize("Steam Mod Guardian",out context);if(hr<0||context==IntPtr.Zero){error=hr<0?ExplainInitializationError(hr):"初始化未返回有效上下文";context=IntPtr.Zero;}}catch(Exception ex){error=ex.GetType().Name;}}
    public static Analysis Classify(Analysis original,int code)
    {
        if(code>=32768)return Add(original,Risk.Critical,"引擎检出恶意内容","AMSI 恶意内容检出",code);
        if(code>=16384&&code<=20479)return Add(original,Risk.High,"引擎策略阻止","AMSI 管理策略阻止（不等于恶意定论）",code);
        if(code<0)return Failed(original,"无效结果");
        if(code>1)return Add(original,Risk.Review,"引擎返回风险值","AMSI 提供程序风险值（需人工核实）",code);
        return original with {AmsiStatus="未检出（非安全证明）"};
    }
    static Analysis Add(Analysis a,Risk risk,string status,string rule,int code)=>a with {Risk=RiskFusion.Merge(a.Risk,risk),AmsiStatus=status,Evidence=a.Evidence.Append(new Evidence(rule,risk,"Windows AMSI",$"返回值 {code}；不执行样本")).ToList()};
    static Analysis Failed(Analysis a,string reason)=>a with {Risk=RiskFusion.Merge(a.Risk,Risk.Unknown),AmsiStatus="失败："+reason};
    public Analysis Apply(byte[] bytes,string hash,string extension,Analysis a,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();if(error!=null||context==IntPtr.Zero)return Failed(a,error??"引擎不可用");
        if(bytes.Length==0)return a with {AmsiStatus="空文件（未扫描）"};
        if(bytes.Length>16*1024*1024)return Failed(a,"超过 16 MiB AMSI 上限");
        try{int hr=AmsiScanBuffer(context,bytes,(uint)bytes.Length,"mod-"+hash+extension,IntPtr.Zero,out int code);ct.ThrowIfCancellationRequested();return hr<0?Failed(a,$"0x{hr:X8}"):Classify(a,code);}
        catch(OperationCanceledException){throw;}catch(Exception ex){return Failed(a,ex.GetType().Name);}
    }
    public void Dispose(){if(context!=IntPtr.Zero){AmsiUninitialize(context);context=IntPtr.Zero;}}
}
public static class RiskFusion
{
    public static Risk Merge(Risk a,Risk b){if(a==Risk.Critical||b==Risk.Critical)return Risk.Critical;if(a==Risk.High||b==Risk.High)return Risk.High;if(a==Risk.Unknown||b==Risk.Unknown)return Risk.Unknown;if(a==Risk.Review||b==Risk.Review)return Risk.Review;return Risk.Clear;}
}
