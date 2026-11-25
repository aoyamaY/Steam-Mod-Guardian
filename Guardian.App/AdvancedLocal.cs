using Guardian.Core;
using Microsoft.Win32;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Text;
namespace Guardian.App;
public partial class MainWindow
{
    private async void YaraX_Click(object sender,RoutedEventArgs e)
    {
        if(Busy)return;if(GlassMessage.Show(this,"从 YARA-X 官方仓库 VirusTotal/yara-x 获取 Windows 版 yr.exe，完整解压到可信目录。不会自动下载或执行模组。配置成功将替换传统 YARA 引擎（仅本次会话）。","配置 YARA-X",MessageBoxButton.OKCancel)!=MessageBoxResult.OK)return;
        SetMaintenance(true);try{var dlg=new OpenFileDialog{Title="选择官方 yr.exe",Filter="YARA-X|yr.exe",CheckFileExists=true};if(dlg.ShowDialog(this)!=true)return;var roots=ReadRoots().Concat(catalog.SelectMany(g=>g.Roots)).ToArray();var rule=Path.Combine(AppContext.BaseDirectory,"rules","guardian.yar");var candidate=new YaraScan(dlg.FileName,rule,true);if(roots.Any(candidate.IsInside)||Quarantine.Inside(dlg.FileName,Quarantine.DefaultVault))throw new IOException("请使用独立可信目录");
            var test=await Task.Run(()=>{var marker=Encoding.UTF8.GetBytes("Guardian harmless YARA-X configuration test");var a=new Analysis(Risk.Clear,"self-test",[]);var normal=candidate.Apply(marker,a,CancellationToken.None);if(normal.YaraStatus.StartsWith("失败："))throw new IOException(normal.YaraStatus);string tmp=Path.Combine(Path.GetTempPath(),"guardian-"+Guid.NewGuid().ToString("N")+".yar");try{File.WriteAllText(tmp,"rule Guardian_YaraX_SelfTest { strings: $s = \"Guardian harmless YARA-X configuration test\" condition: $s }");return new YaraScan(dlg.FileName,tmp,true).Apply(marker,a,CancellationToken.None);}finally{File.Delete(tmp);}});
            if(closed)return;if(!test.Evidence.Any(x=>x.Rule=="YARA-X 特征命中"&&x.Detail.StartsWith("Guardian_YaraX_SelfTest")))throw new IOException("YARA-X 阳性自检失败："+test.YaraStatus);yara=candidate;InvalidateReport();YaraText.Text="YARA-X 已启用 · 配置自检通过";Status.Text="请重新扫描。";
        }catch(Exception ex){if(!closed)GlassMessage.Show(this,ex.Message,"YARA-X 配置失败");}finally{if(!closed)SetMaintenance(false);}
    }
    private void LocalTools_Click(object sender,RoutedEventArgs e)
    {
        if(Busy||report==null||Results.SelectedItem is not ScanRow row){GlassMessage.Show(this,"先扫描并选中一个结果。");return;}
        var roots=report.Roots.Concat(catalog.SelectMany(g=>g.Roots)).ToArray();var w=new GlassWindow(this,"本地专业分析 · 可选",700,580);var panel=new DockPanel{Margin=new Thickness(12)};var top=new StackPanel();DockPanel.SetDock(top,Dock.Top);panel.Children.Add(top);top.Children.Add(new TextBlock{Text="选用官方独立分析器，只分析文件副本。无需联网；请从官方仓库取得工具并核验来源，不要选择 Mod 内的 EXE。结果为独立辅助报告，不改变主扫描风险。",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,0,0,10)});var select=new ComboBox{ItemsSource=new[]{"capa","FLOSS","TLSH"},SelectedIndex=0,Margin=new Thickness(0,0,0,8)};top.Children.Add(select);var reference=new CheckBox{Content="TLSH：另外选择一个参考文件进行距离比较",IsChecked=false};top.Children.Add(reference);var start=w.ActionButton("选择可信引擎并分析",true);var stop=w.ActionButton("取消分析");stop.IsEnabled=false;var bar=new WrapPanel();bar.Children.Add(start);bar.Children.Add(stop);top.Children.Add(bar);var output=new TextBox{IsReadOnly=true,AcceptsReturn=true,TextWrapping=TextWrapping.Wrap,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};panel.Children.Add(output);w.SetBody(panel);CancellationTokenSource? cancellation=null;bool done=false;
        w.Closed+=(_,_)=>{done=true;cancellation?.Cancel();};stop.Click+=(_,_)=>cancellation?.Cancel();start.Click+=async(_,_)=>{if(cancellation!=null||select.SelectedItem is not string kind)return;var dlg=new OpenFileDialog{Title="选择可信 "+kind+" EXE",Filter="EXE|*.exe",CheckFileExists=true};if(dlg.ShowDialog(w)!=true)return;string? other=null;if(kind=="TLSH"&&reference.IsChecked==true){var pick=new OpenFileDialog{Title="选择用于比较的参考文件（只读取）"};if(pick.ShowDialog(w)!=true)return;other=pick.FileName;}if(GlassMessage.Show(w,"将运行你选择的第三方分析器。请确认来源可信；分析器自身不是沙箱。不会执行目标文件。","确认本地分析",MessageBoxButton.OKCancel)!=MessageBoxResult.OK)return;using var c=new CancellationTokenSource();cancellation=c;start.IsEnabled=false;stop.IsEnabled=true;output.Text="正在本地分析…";try{var result=await Task.Run(()=>LocalTools.Analyze(row,kind,dlg.FileName,roots,other,c.Token));if(!done)output.Text=result;}catch(Exception ex){if(!done)output.Text="未完成："+ex.Message;}finally{cancellation=null;if(!done){start.IsEnabled=true;stop.IsEnabled=false;}}};w.ShowModal();
    }
}
