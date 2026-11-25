using System.Diagnostics;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
namespace Guardian.App;
internal static class EtwObserver
{
    internal static string Observe(int pid,DateTime start,CancellationToken ct)
    {
        if(TraceEventSession.IsElevated()!=true)throw new InvalidOperationException("ETW 内核事件需要管理员权限；普通 TCP/模块观察无需提升权限。");
        using var process=Process.GetProcessById(pid);if(process.StartTime!=start||process.HasExited)throw new InvalidOperationException("进程已变化");
        using var session=new TraceEventSession("SteamModGuardian-"+Guid.NewGuid().ToString("N"));var counts=new System.Collections.Concurrent.ConcurrentDictionary<string,long>();
        session.Source.Kernel.All+=e=>{if(e.ProcessID!=pid)return;var name=e.EventName; if(counts.Count<128||counts.ContainsKey(name))counts.AddOrUpdate(name,1,(_,v)=>v+1);};
        session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process|KernelTraceEventParser.Keywords.ImageLoad|KernelTraceEventParser.Keywords.NetworkTCPIP|KernelTraceEventParser.Keywords.FileIO|KernelTraceEventParser.Keywords.FileIOInit);
        using var timer=new System.Threading.Timer(_=>{try{if(process.HasExited||process.StartTime!=start)session.Stop();}catch{try{session.Stop();}catch{}}},null,1000,1000);
        using var limit=CancellationTokenSource.CreateLinkedTokenSource(ct);limit.CancelAfter(TimeSpan.FromSeconds(60));using var stop=limit.Token.Register(()=>{try{session.Stop();}catch{}});
        session.Source.Process();ct.ThrowIfCancellationRequested();return "ETW 事件计数（仅指定 PID，不含事件数据；可能丢失事件）\n"+string.Join("\n",counts.OrderByDescending(x=>x.Value).Select(x=>$"{x.Key}: {x.Value}"));
    }
}
