using Guardian.Core;
using System.IO;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
namespace Guardian.App;
public partial class MainWindow
{
    private Dictionary<string,List<string>> extraRoots=new(StringComparer.OrdinalIgnoreCase);
    private List<string> unassignedRoots=[];
    private bool profileLoaded;
    private RuntimeMonitorWindow? runtimeWindow;
    private void RestoreProfile()
    {
        if(profileLoaded)return;profileLoaded=true;
        try{var p=ProfileStore.Load<UserProfile>("profile-v2.json");if(p==null)return;selectedIds.Clear();foreach(var id in p.SelectedIds.Where(SteamCatalog.Id))selectedIds.Add(id);extraRoots=p.ExtraRoots;unassignedRoots=p.UnassignedRoots;MonitorBox.IsChecked=p.Monitor;TitleBox.IsChecked=p.QueryTitles;RootsBox.Text=string.Join(Environment.NewLine,ProfileStore.RootsFor(catalog.Where(g=>selectedIds.Contains(g.AppId)),extraRoots,unassignedRoots));}
        catch(Exception ex){StartupLog.Write("Profile load failed: "+ex);Status.Text="配置读取失败，请重新选择游戏。";}
    }
    private void CaptureProfile()
    {
        var actual=ReadRoots();var auto=catalog.Where(g=>selectedIds.Contains(g.AppId)).SelectMany(g=>g.Roots).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var extras=actual.Where(r=>!auto.Contains(r)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if(selectedIds.Count==1){var id=selectedIds.Single();unassignedRoots=unassignedRoots.Where(r=>extras.Contains(r,StringComparer.OrdinalIgnoreCase)).ToList();extraRoots[id]=extras.Where(r=>!unassignedRoots.Contains(r,StringComparer.OrdinalIgnoreCase)).ToList();}
        else {foreach(var id in selectedIds)if(extraRoots.TryGetValue(id,out var old))extraRoots[id]=old.Where(r=>extras.Contains(r,StringComparer.OrdinalIgnoreCase)).ToList();var assigned=selectedIds.Where(extraRoots.ContainsKey).SelectMany(id=>extraRoots[id]).ToHashSet(StringComparer.OrdinalIgnoreCase);unassignedRoots=extras.Where(r=>!assigned.Contains(r)).ToList();}
    }
    private void SaveProfile_Click(object sender,RoutedEventArgs e){if(Busy)return;try{CaptureProfile();PersistProfile();Status.Text="当前游戏配置已保存；单选游戏时添加的额外目录归该游戏，多选时未关联目录为全局目录。";}catch(Exception ex){GlassMessage.Show(this,ex.Message);}}
    private void PersistProfile()=>ProfileStore.Save("profile-v2.json",new UserProfile(selectedIds.ToList(),extraRoots,unassignedRoots,MonitorBox.IsChecked==true,TitleBox.IsChecked==true));
    private void LoadBaseline(string key){try{var saved=ProfileStore.Load<SavedBaseline>(ProfileStore.ScopeFile(key));if(saved?.Key==key){baseline=saved.Rows.ToDictionary(r=>r.Path,StringComparer.OrdinalIgnoreCase);changes.AddRange(saved.Changes.TakeLast(500));}}catch(Exception ex){StartupLog.Write("Baseline load failed: "+ex);}}
    private async Task SaveBaseline(string key){if(baseline==null)return;try{var rows=baseline.Values.Select(r=>r with {Analysis=r.Analysis with {Evidence=[],Fingerprints=null,Hosts=null,FuzzyFingerprints=null}}).ToList();var history=changes.TakeLast(500).ToList();await Task.Run(()=>ProfileStore.Save(ProfileStore.ScopeFile(key),new SavedBaseline(key,rows,history)));}catch(Exception ex){StartupLog.Write("Baseline save failed: "+ex);}}
    private void Roots_Changed(object sender,TextChangedEventArgs e){if(report!=null&&cts==null&&!maintenance)InvalidateReport();}
    private void Search_Changed(object sender,TextChangedEventArgs e){if(report!=null)ApplyFilter();}
    private void RefreshTiles(){UpdateEmptyState();var f=report?.Files;TotalTile.Text=f?.Count.ToString()??"—";RiskTile.Text=f?.Count(r=>r.Analysis.Risk is Risk.High or Risk.Critical).ToString()??"—";UnknownTile.Text=f?.Count(r=>r.Analysis.Risk==Risk.Unknown).ToString()??"—";DownloadTile.Text=f?.Count(r=>r.DownloadLabel is "直接文件下载 API" or "疑似下载落盘" or "联网+写入（待核实）").ToString()??"—";}
    private void UpdateSelection(ScanRow? row){if(SelectionTitle==null)return;ExplainSelection(row);SelectionTitle.Text=row==null?"选中一行查看证据":row.Mod+" / "+row.FileName;QuarantineBtn.IsEnabled=row!=null&&(row.Analysis.Risk is Risk.High or Risk.Critical)&&row.Sha256.Length>0;WorkshopBtn.IsEnabled=row!=null&&ulong.TryParse(row.WorkshopId,out _);HashBtn.IsEnabled=row?.Sha256.Length==64;EvidenceBtn.IsEnabled=row!=null;}
    private void Runtime_Click(object sender,RoutedEventArgs e){if(runtimeWindow!=null){runtimeWindow.Activate();return;}runtimeWindow=new RuntimeMonitorWindow(this);runtimeWindow.Closed+=(_,_)=>runtimeWindow=null;runtimeWindow.Show();}
    private void Domains_Click(object sender,RoutedEventArgs e){try{Scanner.EnsureData();var p=Path.Combine(Scanner.DataDir,"domains.txt");if(!File.Exists(p))File.WriteAllText(p,"# 每行一个经核实的域名/IP；可匹配子域名。默认空名单。\n");Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"notepad.exe")){UseShellExecute=false,ArgumentList={p}});}catch(Exception ex){GlassMessage.Show(this,ex.Message);}}
    private async void Reputation_Click(object sender,RoutedEventArgs e)
    {
        if(Results.SelectedItem is not ScanRow row){GlassMessage.Show(this,"先选择一个检测结果。");return;}
        var w=new GlassWindow(this,"VirusTotal 信誉查询",620,480);var panel=new StackPanel{Margin=new Thickness(16)};
        panel.Children.Add(new TextBlock{Text="仅向 VirusTotal 发送所选 SHA-256 或域名。不会上传文件或完整 URL；API Key 仅在此次窗口内使用。检测引擎意见不能证明安全。",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,0,0,12)});
        var pass=new PasswordBox{Margin=new Thickness(0,4,0,12),Padding=new Thickness(8,5,8,5)};panel.Children.Add(new TextBlock{Text="VirusTotal API Key"});panel.Children.Add(pass);
        var items=new List<(string Value,bool Domain)>();if(row.Sha256.Length==64)items.Add((row.Sha256,false));foreach(var h in row.Analysis.Hosts??[])if(Uri.CheckHostName(h)==UriHostNameType.Dns)items.Add((h,true));if(items.Count==0){GlassMessage.Show(this,"没有可查询的哈希或域名。");return;}
        var pick=new ComboBox{ItemsSource=items.Select(x=>(x.Domain?"域名：":"SHA-256：")+x.Value).ToList(),SelectedIndex=0,Margin=new Thickness(0,4,0,12)};panel.Children.Add(pick);var b=new Button{Content="发送查询"};panel.Children.Add(b);var result=new TextBlock{TextWrapping=TextWrapping.Wrap};panel.Children.Add(result);w.SetBody(new ScrollViewer{Content=panel,VerticalScrollBarVisibility=ScrollBarVisibility.Auto});using var cancel=new CancellationTokenSource();bool ended=false;w.Closed+=(_,_)=>{ended=true;cancel.Cancel();};
        b.Click+=async(_,_)=>{if(pick.SelectedIndex<0)return;var item=items[pick.SelectedIndex];b.IsEnabled=false;result.Text="正在查询…";try{var r=await ReputationClient.QueryAsync(pass.Password,item.Value,item.Domain,cancel.Token);if(!ended)result.Text=$"{r.Status}\n恶意：{r.Malicious} · 可疑：{r.Suspicious} · 无害：{r.Harmless} · 未检出：{r.Undetected}\n报告时间：{r.AnalysisTime?.ToLocalTime().ToString("g")??"未知"}";}catch(OperationCanceledException){if(!ended)result.Text="查询已取消或超时";}catch(Exception ex){if(!ended)result.Text="查询失败："+ex.GetType().Name;}finally{if(!ended)b.IsEnabled=true;}};w.ShowModal();pass.Clear();await Task.CompletedTask;
    }
}
