using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.IO;
using Microsoft.Win32;
using Guardian.Core;
namespace Guardian.App;
internal static class TcpSnapshot
{
    [DllImport("iphlpapi.dll",ExactSpelling=true)]private static extern uint GetExtendedTcpTable(IntPtr table,ref int size,[MarshalAs(UnmanagedType.Bool)]bool order,int family,int tableClass,uint reserved);
    public static List<string> Remote(int pid)
    {
        var result=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(int family in new[]{2,23})
        {
            int size=0;uint code=GetExtendedTcpTable(IntPtr.Zero,ref size,false,family,5,0);if(code!=122&&code!=0)throw new IOException("TCP 表错误 "+code);
            for(int attempt=0;attempt<3;attempt++)
            {
                if(size<4||size>32*1024*1024)throw new IOException("TCP 表大小异常");int allocated=size;IntPtr ptr=Marshal.AllocHGlobal(allocated);
                try
                {
                    code=GetExtendedTcpTable(ptr,ref size,false,family,5,0);if(code==122)continue;if(code!=0)throw new IOException("TCP 表错误 "+code);
                    int count=Marshal.ReadInt32(ptr),rowSize=family==2?24:56;if(count<0||count>(allocated-4)/rowSize)throw new IOException("TCP 表越界");
                    for(int i=0;i<count;i++){IntPtr row=IntPtr.Add(ptr,4+i*rowSize);int owner=Marshal.ReadInt32(row,family==2?20:52);if(owner!=pid)continue;int state=Marshal.ReadInt32(row,family==2?0:48);if(state is 1 or 2 or 12)continue;
                        byte[] address=new byte[family==2?4:16];Marshal.Copy(IntPtr.Add(row,family==2?12:24),address,0,address.Length);var ip=family==2?new IPAddress(address):new IPAddress(address,(uint)Marshal.ReadInt32(row,40));int portOffset=family==2?16:44;int port=Marshal.ReadByte(row,portOffset)*256+Marshal.ReadByte(row,portOffset+1);if(port==0||ip.Equals(IPAddress.Any)||ip.Equals(IPAddress.IPv6Any))continue;
                        result.Add(new IPEndPoint(ip,port).ToString());}
                    break;
                }finally{Marshal.FreeHGlobal(ptr);}
            }
            if(code!=0)throw new IOException("TCP 表持续变化，采样失败");
        }return result.OrderBy(x=>x).ToList();
    }
}
internal sealed class RuntimeMonitorWindow:GlassWindow
{
    private sealed record Target(int Id,string Name,DateTime Start){public string Label=>$"{Name}  ·  PID {Id}";}
    private sealed record Sample(List<string> Endpoints,List<string> Modules,string? ModuleError);
    readonly ComboBox processes=new(){DisplayMemberPath="Label",MinWidth=300};readonly TextBox log=new(){IsReadOnly=true,AcceptsReturn=true,TextWrapping=TextWrapping.Wrap,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
    readonly TextBlock status=new(){Text="未监控",TextWrapping=TextWrapping.Wrap};readonly DispatcherTimer timer=new(){Interval=TimeSpan.FromSeconds(2)};
    readonly HashSet<string> seenEndpoints=new(),seenModules=new(StringComparer.OrdinalIgnoreCase),blockedIps=new(StringComparer.OrdinalIgnoreCase);Target? target;bool busy,closed,first;int generation;bool moduleBaseline;
    public RuntimeMonitorWindow(Window owner) : base(owner,"运行时观察 · TCP / 已加载模块",950,650)
    {
        MinWidth=650;MinHeight=420;
        var panel=new DockPanel{Margin=new Thickness(16)};var top=new StackPanel();DockPanel.SetDock(top,Dock.Top);panel.Children.Add(top);
        top.Children.Add(new TextBlock{Text="选择已运行的游戏进程。每 2 秒采样 TCP 远端与已加载模块；新连接只是线索，不能归因于某个 Mod。不会抓包、解密或阻断连接。",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,0,0,12)});
        var bar=new WrapPanel{Margin=new Thickness(0,0,0,8)};top.Children.Add(bar);bar.Children.Add(processes);
        void Button(string label,Action action){var b=new Button{Content=label};b.Click+=(_,_)=>action();bar.Children.Add(b);}
        Button("ETW 60 秒观察",StartEtw);Button("刷新进程",Refresh);Button("开始观察",Start);Button("停止",Stop);Button("导出日志",Export);Button("清空日志",()=>log.Clear());top.Children.Add(status);panel.Children.Add(log);SetBody(panel);timer.Tick+=async(_,_)=>await Tick();Refresh();
    }
    CancellationTokenSource? etwCancellation;
    async void StartEtw(){if(etwCancellation!=null||processes.SelectedItem is not Target t)return;if(GlassMessage.Show(this,"ETW 会在 60 秒内收集内核事件，只保留所选 PID 的事件类型和数量，不保存其他进程事件或负载。需要管理员权限；不注入、不执行模组。是否继续？","ETW 观察",MessageBoxButton.OKCancel)!=MessageBoxResult.OK)return;using var c=new CancellationTokenSource();etwCancellation=c;Append("ETW 观察开始（最多 60 秒）");try{var result=await Task.Run(()=>EtwObserver.Observe(t.Id,t.Start,c.Token));if(!closed)Append(result);}catch(Exception ex){if(!closed)Append("ETW 未完成："+ex.Message);}finally{etwCancellation=null;}}
    void Refresh(){if(target!=null)return;var list=new List<Target>();foreach(var p in Process.GetProcesses()){using(p){try{if(p.Id!=Environment.ProcessId)list.Add(new(p.Id,p.ProcessName,p.StartTime));}catch{}}}processes.ItemsSource=list.OrderBy(x=>x.Name).ToList();}
    void Start(){if(target!=null||busy||processes.SelectedItem is not Target t)return;target=t;generation++;seenEndpoints.Clear();seenModules.Clear();blockedIps.Clear();try{var path=Path.Combine(Scanner.DataDir,"domains.txt");if(File.Exists(path)&&new FileInfo(path).Length<=1024*1024)foreach(var line in File.ReadLines(path))if(IPAddress.TryParse(line.Split('#')[0].Trim(),out var ip))blockedIps.Add(ip.ToString());}catch(Exception ex){Append("本地 IP 名单不可用："+ex.Message);}first=true;moduleBaseline=false;processes.IsEnabled=false;timer.Start();Append("开始观察 "+t.Label);_ = Tick();}
    void Stop(){etwCancellation?.Cancel();generation++;timer.Stop();target=null;processes.IsEnabled=true;status.Text="已停止";}
    static Sample Collect(Target t){using var p=Process.GetProcessById(t.Id);if(p.StartTime!=t.Start||p.HasExited)throw new IOException("进程已退出或 PID 已重用");var endpoints=TcpSnapshot.Remote(t.Id);var modules=new List<string>();string? error=null;try{foreach(ProcessModule m in p.Modules){using(m){modules.Add(m.FileName);}}}catch(Exception){error="模块列表不可读（权限/架构限制）";}p.Refresh();if(p.HasExited||p.StartTime!=t.Start)throw new IOException("进程已退出或 PID 已重用");return new(endpoints,modules,error);}
    async Task Tick(){if(busy||target==null||closed)return;busy=true;var t=target;int g=generation;try{var s=await Task.Run(()=>Collect(t));if(closed||g!=generation)return;foreach(var x in s.Endpoints)if(seenEndpoints.Add(x)){bool blocked=IPEndPoint.TryParse(x,out var ep)&&blockedIps.Contains(ep.Address.ToString());Append((blocked?"警告：命中本地 IP 名单 ":first?"基线 TCP ":"新观察 TCP（待复核） ")+x);}if(s.ModuleError==null){foreach(var x in s.Modules)if(seenModules.Add(x)&&moduleBaseline)Append("新观察模块（待复核） "+x);moduleBaseline=true;}status.Text=$"{t.Label} · 当前 TCP 远端 {s.Endpoints.Count} · 已观察 {seenEndpoints.Count} · 模块 {s.Modules.Count} {s.ModuleError}";first=false;if(seenEndpoints.Count+seenModules.Count>20000){Append("记录达到上限，请重新开始观察");Stop();}}
        catch(Exception ex){if(!closed&&g==generation){Append("观察失败："+ex.Message);Stop();}}finally{busy=false;}}
    void Append(string s){if(log.Text.Length>500000)log.Text=log.Text[^400000..];log.AppendText($"{DateTime.Now:HH:mm:ss}  {s}\n");log.ScrollToEnd();}
    void Export(){var dlg=new SaveFileDialog{Filter="文本日志|*.txt",FileName="guardian-runtime.txt"};if(dlg.ShowDialog(this)==true)try{File.WriteAllText(dlg.FileName,log.Text);}catch(Exception ex){GlassMessage.Show(this,ex.Message);}}
    protected override void OnClosed(EventArgs e){closed=true;Stop();base.OnClosed(e);}
}
