using Guardian.Core;
using System.IO;
using System.Windows;
namespace Guardian.App;
public partial class MainWindow
{
    private CancellationTokenSource? quickYaraCancellation;
    private async void QuickYara_Click(object sender,RoutedEventArgs e)
    {
        if(Busy||showingGuide)return;
        var previous=yara;var oldText=YaraText.Text;
        var roots=ReadRoots().Concat(catalog.SelectMany(g=>g.Roots)).ToArray();
        var rules=Path.Combine(AppContext.BaseDirectory,"rules","guardian.yar");
        SetMaintenance(true);SetProgressState(true);Progress.Visibility=Visibility.Collapsed;TaskProgressLabel.Text="正在配置 YARA · 阶段进度";using var cancel=new CancellationTokenSource();quickYaraCancellation=cancel;
        var progress=new Progress<string>(text=>{if(!closed&&quickYaraCancellation==cancel){YaraText.Text=text;Status.Text=text;TaskProgressLabel.Text="正在配置 YARA";}});
        try
        {
            var candidate=await Task.Run(()=>YaraInstaller.InstallAsync(rules,roots,progress,cancel.Token));
            if(closed)return;
            yara=candidate;InvalidateReport();YaraText.Text="YARA 已启用 · 官方包校验及自检通过";
            Status.Text="YARA 配置完成。请重新扫描；文件下载能力或疑似落盘按极高风险处理。";
        }
        catch(OperationCanceledException){if(!closed){YaraText.Text=previous==null?"YARA 未启用 · 下载取消或超时":oldText;Status.Text="YARA 配置取消或超时，原有配置未改变。";}}
        catch(Exception ex){if(!closed){YaraText.Text=previous==null?"YARA 未启用 · 自动配置失败":oldText;Status.Text="YARA 自动配置失败，原有配置未改变。";StartupLog.Write("Quick YARA: "+ex);GlassMessage.Show(this,ex.Message+"\n\n请检查 GitHub 网络连接，或使用高级检测工具中的手动配置。不会运行未通过校验的安装包。","YARA 自动配置失败",MessageBoxButton.OK,MessageBoxImage.Warning);}}
        finally{quickYaraCancellation=null;if(!closed){Progress.Visibility=Visibility.Visible;SetProgressState(false);SetMaintenance(false);}}
    }
}
