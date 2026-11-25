using Guardian.Core;
using System.Windows;
using System.Windows.Controls;
namespace Guardian.App;
public partial class MainWindow
{
    private sealed record GuidePreference(bool Seen);
    private bool showingGuide;
    private async Task FirstGuideAsync()
    {
        try{if(ProfileStore.Load<GuidePreference>("guide-v202.json")?.Seen==true)return;}catch(Exception ex){StartupLog.Write("Guide state: "+ex.Message);}
        if(!closed)await ShowGuideAsync();
    }
    private async void Help_Click(object sender,RoutedEventArgs e){if(!Busy&&!showingGuide)await ShowGuideAsync();}
    private async Task ShowGuideAsync()
    {
        if(Busy||showingGuide)return;
        showingGuide=true;int choice=0;
        var w=new GlassWindow(this,"欢迎使用 · 快速入门",620,485,false);
        var panel=new DockPanel{Margin=new Thickness(12)};var actions=new WrapPanel{HorizontalAlignment=HorizontalAlignment.Right};DockPanel.SetDock(actions,Dock.Bottom);panel.Children.Add(actions);
        var back=w.ActionButton("上一步");var next=w.ActionButton("下一步",true);var skip=w.ActionButton("稍后再说");actions.Children.Add(skip);actions.Children.Add(back);actions.Children.Add(next);
        var content=new StackPanel();panel.Children.Add(new ScrollViewer{Content=content,VerticalScrollBarVisibility=ScrollBarVisibility.Auto});w.SetBody(panel);
        int step=0;var online=new CheckBox{Content="在线获取实际工坊 Mod 名称（仅发送工坊 ID）",IsChecked=TitleBox.IsChecked};
        var pages=new (string Head,string Body)[]{("01 / 选择范围","软件会识别本机 Steam 游戏和已有工坊目录。可选一个游戏，也可以检查所有已识别的模组目录；不会默认扫描游戏本体。其他本地 Mod 目录需手动添加。"),("02 / 理解风险","红色：高危线索，优先人工复核。\n黄色：需复核，联网不等于木马。\n紫色：未知或检查不完整。\n绿色：当前未发现风险，不保证安全。"),("03 / 开始检查","推荐扫描使用哈希缓存；变化文件会重新分析。不执行、不删除任何 Mod；默认不提交样本。可主动开启 Windows 防病毒引擎，提供程序可能使用云保护。隔离、联网信誉查询及安全启动都需要你主动操作。")};
        void Render(){content.Children.Clear();content.Children.Add(new TextBlock{Text=pages[step].Head,FontSize=25,FontWeight=FontWeights.SemiBold,Margin=new Thickness(0,6,0,18)});content.Children.Add(new TextBlock{Text=pages[step].Body,TextWrapping=TextWrapping.Wrap,LineHeight=25,FontSize=15,Margin=new Thickness(0,0,0,20)});if(step==2){content.Children.Add(online);content.Children.Add(new TextBlock{Text=$"已识别 {catalog.Count} 个游戏，{catalog.Count(g=>g.Roots.Count>0)} 个有自动扫描目录。",TextWrapping=TextWrapping.Wrap,Foreground=w.Brush("SubtleBrush"),Margin=new Thickness(0,12,0,0)});}back.IsEnabled=step>0;next.Content=step==2?"开始推荐扫描":"下一步";}
        back.Click+=(_,_)=>{if(step>0){step--;Render();}};next.Click+=(_,_)=>{if(step<2){step++;Render();}else{choice=1;w.DialogResult=true;}};skip.Click+=(_,_)=>{choice=2;w.DialogResult=false;};Render();
        try{w.ShowModal();if(choice==1){TitleBox.IsChecked=online.IsChecked;try{PersistProfile();}catch(Exception ex){StartupLog.Write("Guide profile: "+ex.Message);}}if(choice!=0)try{ProfileStore.Save("guide-v202.json",new GuidePreference(true));}catch(Exception ex){StartupLog.Write("Guide save: "+ex.Message);}}
        finally{showingGuide=false;}
        if(choice==1&&!closed)await RecommendedScanAsync();
    }
    private async void Recommended_Click(object sender,RoutedEventArgs e)=>await RecommendedScanAsync();
    private async Task RecommendedScanAsync()
    {
        if(Busy||showingGuide)return;
        if(ReadRoots().Length==0)
        {
            var available=catalog.Where(g=>g.Roots.Count>0||extraRoots.TryGetValue(g.AppId,out var r)&&r.Count>0).ToList();
            if(available.Count==0){GlassMessage.Show(this,"没有识别到可以检查的模组目录。请刷新 Steam 游戏库，或在高级设置中添加本地 Mod 目录。");AdvancedPanel.Visibility=Visibility.Visible;return;}
            if(GlassMessage.Show(this,$"当前没有扫描目录。是否选择 {available.Count} 个有已知模组目录的游戏并检查？\n\n不会扫描整个游戏本体，不会删除文件。其他本地模组目录需要手动添加。","推荐扫描范围",MessageBoxButton.OKCancel)!=MessageBoxResult.OK)return;
            SetGames(available);
        }
        // Respect current scope, preserve opt-in network and monitor settings, never change quarantine state.
        ForceBox.IsChecked=false;FilterBox.SelectedIndex=0;SearchBox.Clear();await RunScan(false);
    }
    private async void AmsiConsent_Click(object sender,RoutedEventArgs e)
    {
        if(AmsiBox==null||!IsLoaded)return;
        if(Busy||GlassMessage.Show(this,"增强检测将文件内容交给 Windows 注册的反恶意软件提供程序（通常是 Defender）。本工具不直接上传样本，但提供程序可能按自身云保护/样本提交策略联网或处理文件。扫描可能变慢。此选项仅本次运行生效。是否开启？","启用增强检测",MessageBoxButton.OKCancel,MessageBoxImage.Warning)!=MessageBoxResult.OK){AmsiBox.IsChecked=false;return;}
        SetMaintenance(true);AmsiText.Text="正在检查 Windows AMSI 初始化…";
        try
        {
            var error=await Task.Run(()=>{using var engine=new AmsiEngine();return engine.IsAvailable?null:engine.InitializationError??"无有效上下文";});
            if(closed)return;
            InvalidateReport();
            if(error!=null)
            {
                AmsiBox.IsChecked=false;
                AmsiText.Text="AMSI 不可用："+error;
                Status.Text="AMSI 初始化失败，未启用增强检测。静态检测仍可使用；修复系统安全提供程序后可重新勾选。";
                StartupLog.Write("AMSI preflight: "+error);
                GlassMessage.Show(this,error+"\n\n请在 Windows 安全中心检查病毒和威胁防护及安全提供程序。可在 PowerShell 运行 Get-MpComputerStatus 查看 Defender 状态。不要关闭、绕过或篡改安全软件。\n\n本次没有启用 AMSI；可继续使用静态检测和 YARA，但不能将未检出视为安全。","AMSI 不可用",MessageBoxButton.OK,MessageBoxImage.Warning);
            }
            else {AmsiText.Text="AMSI 初始化通过（扫描时仍需确认结果）";Status.Text="增强检测已开启；扫描时使用 Windows AMSI。";}
        }
        catch(Exception ex){if(!closed){AmsiBox.IsChecked=false;AmsiText.Text="AMSI 自检失败："+ex.Message;StartupLog.Write("AMSI preflight failed: "+ex);InvalidateReport();}}
        finally{if(!closed)SetMaintenance(false);}
    }
    private void AmsiDisabled_Click(object sender,RoutedEventArgs e){if(AmsiBox!=null&&IsLoaded&&!Busy){InvalidateReport();AmsiText.Text="AMSI 未启用";Status.Text="增强检测已关闭；下次扫描仍使用静态检测。";}}
    private void Advanced_Click(object sender,RoutedEventArgs e)=>AdvancedPanel.Visibility=AdvancedPanel.Visibility==Visibility.Visible?Visibility.Collapsed:Visibility.Visible;
    private void Tools_Click(object sender,RoutedEventArgs e)=>ToolsPanel.Visibility=ToolsPanel.Visibility==Visibility.Visible?Visibility.Collapsed:Visibility.Visible;
    private void ClearSearch_Click(object sender,RoutedEventArgs e){SearchBox.Clear();FilterBox.SelectedIndex=0;}
    private void HighFilter_Click(object sender,RoutedEventArgs e)=>SetFilter("高危及极高风险");
    private void DownloadFilter_Click(object sender,RoutedEventArgs e)=>SetFilter("直接/疑似文件下载");
    private void SetFilter(string text){foreach(var item in FilterBox.Items.OfType<ComboBoxItem>())if(item.Content as string==text){FilterBox.SelectedItem=item;break;}}
    private void UpdateEmptyState()
    {
        if(EmptyPanel==null||Results==null)return;
        bool visible=Results.Items.Count==0;EmptyPanel.Visibility=visible?Visibility.Visible:Visibility.Collapsed;
        if(!visible)return;
        if(cts!=null&&report==null){EmptyTitle.Text="正在检查模组";EmptyHint.Text="请查看底部进度；可取消当前任务。";}
        else if(report==null){EmptyTitle.Text="还没有扫描结果";EmptyHint.Text="点击左侧“一键推荐扫描”，开始检查模组。";}
        else if(report.Files.Count==0){EmptyTitle.Text="未找到可检查文件";EmptyHint.Text="检查扫描目录及扫描警告。这并不表示游戏安全。";}
        else {EmptyTitle.Text="没有匹配的结果";EmptyHint.Text="尝试清空搜索条件或切换风险筛选。";}
    }
    private void ExplainSelection(ScanRow? row)
    {
        if(RiskExplanation==null)return;
        RiskExplanation.Text=row==null?"选中结果后，会显示风险含义和推荐操作。":row.Analysis.Risk switch{
            Risk.Critical=>"极高风险：发现文件下载能力、严重行为组合或名单线索。先停止使用此 Mod，人工核对证据。确认恶意后取消订阅或隔离。",
            Risk.High=>"高风险：存在敏感行为。先查看证据，必要时向作者或安全人员核实，再决定是否隔离。",
            Risk.Review=>"需复核：这些能力也可能用于正常功能。检查联网、下载及文件写入用途，不要仅凭此结果删除。",
            Risk.Unknown=>"未知：无法完成部分分析或不支持此类型，不能判断安全。请查看错误与扫描警告。",
            _=>"未发现风险：现有规则没有发现风险线索，不代表绝对安全。"};
        if(row!=null&&DownloadRiskPolicy.IsFileDownload(row.DownloadLabel))RiskExplanation.Text+="\n文件下载能力或疑似落盘按极高风险处理，不代表已实际下载或确认恶意。";
        else if(row?.DownloadLabel=="联网+写入（待核实）")RiskExplanation.Text+="\n仅发现联网与写入共现，尚无下载数据落盘依据；请核对用途。";
    }
}
