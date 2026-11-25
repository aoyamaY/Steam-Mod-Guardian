using Guardian.Core;
using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
namespace Guardian.App;
public partial class MainWindow : Window
{
    private ScanReport? report;
    private CancellationTokenSource? cts;
    private bool detecting;
    private bool closed;
    private readonly System.Windows.Threading.DispatcherTimer monitor=new(){Interval=TimeSpan.FromSeconds(60)};
    private Dictionary<string,ScanRow>? baseline;
    private string baselineRoots="";
    private readonly List<string> changes=new();
    private YaraScan? yara;
    private bool syncing;
    public MainWindow() : this(false) { }
    internal MainWindow(bool smokeTest)
    {
        StartupLog.Write("MainWindow.InitializeComponent begin");
        InitializeComponent();
        MinimizeButton.Content=FeatherIcons.Make("minus"); MaximizeButton.Content=FeatherIcons.Make("square"); CloseButton.Content=FeatherIcons.Make("x"); EmptyIcon.Content=FeatherIcons.Make("search",36,System.Windows.Media.Brushes.LightSteelBlue);
        StateChanged+=(_,_)=>MaximizeButton.Content=FeatherIcons.Make(WindowState==WindowState.Maximized?"copy":"square");
        FeatherIcons.Label(RecommendedBtn,"shield","一键推荐扫描"); FeatherIcons.Label(QuickYaraBtn,"download","一键下载并启用 YARA"); FeatherIcons.Label(ExportBtn,"file","导出报告");
        UpdateTileSelection();
        AcrylicChrome.Attach(this,AcrylicSurface);
        StartupLog.Write("MainWindow.InitializeComponent complete");
        if (!smokeTest) { ContentRendered += FirstRender; monitor.Tick+=Monitor_Tick; monitor.Start(); }
    }
    private async void FirstRender(object? sender, EventArgs e)
    {
        ContentRendered -= FirstRender;
        StartupLog.Write("Window rendered");
        await DetectSteamAsync();
        if(!closed)await FirstGuideAsync();
    }
    private async void Detect_Click(object sender,RoutedEventArgs e) => await DetectSteamAsync();
    private async Task DetectSteamAsync()
    {
        if (detecting || closed || cts != null || maintenance) return;
        detecting=true; DetectBtn.IsEnabled=false;
        Status.Text="正在识别 Steam 目录；可手动添加目录，不必等待。";
        StartupLog.Write("Steam detection begin");
        try
        {
            var work=Task.Run(SteamPaths.Detect);
            if (await Task.WhenAny(work,Task.Delay(TimeSpan.FromSeconds(8))) != work)
            {
                StartupLog.Write("Steam detection slow; UI remains available");
                if (!closed && cts==null) Status.Text="Steam 目录识别较慢，可手动添加目录。";
            }
            var found=await work;
            StartupLog.Write($"Steam detection complete; {found.Count} root(s)");
            if (closed || cts!=null) return;
            catalog=WithGameNames(found);
            RestoreProfile();
            selectedIds.RemoveWhere(id=>!catalog.Any(g=>g.AppId==id));
            
            UpdateGameLabel();
            Status.Text=found.Count==0?"未识别本地 Steam 游戏，请手动添加目录。":$"已识别 {found.Count} 个游戏；点击选择游戏设置扫描范围。";
        }
        catch(Exception ex)
        {
            StartupLog.Write("Steam detection failed: "+ex);
            if (!closed && cts==null) Status.Text="Steam 目录识别失败，请手动添加。";
        }
        finally { detecting=false; if(!closed && cts==null) DetectBtn.IsEnabled=true; }
    }
    private string[] ReadRoots() => RootsBox.Text.Split(['\r','\n'],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
    private void Add_Click(object sender,RoutedEventArgs e) { if(maintenance)return; var dlg=new OpenFolderDialog { Title="选择模组目录" }; if(dlg.ShowDialog(this)==true) RootsBox.Text=string.Join(Environment.NewLine,ReadRoots().Append(dlg.FolderName).Distinct(StringComparer.OrdinalIgnoreCase)); }
    private async void Scan_Click(object sender,RoutedEventArgs e) => await RunScan(false);
    private async void Monitor_Tick(object? sender,EventArgs e)
    {
        if(MonitorBox.IsChecked!=true || Busy || showingGuide)return;
        // Discover newly created workshop roots even when the selected game previously had none.
        if(selectedIds.Count>0){detecting=true;try{CaptureProfile();var fresh=await Task.Run(SteamPaths.Detect);if(closed)return;catalog=WithGameNames(fresh);var roots=ProfileStore.RootsFor(catalog.Where(g=>selectedIds.Contains(g.AppId)),extraRoots,unassignedRoots);var old=ReadRoots().ToHashSet(StringComparer.OrdinalIgnoreCase);if(!old.SetEquals(roots))RootsBox.Text=string.Join(Environment.NewLine,roots);UpdateGameLabel();}catch(Exception ex){Status.Text="更新监控识别失败："+ex.Message;return;}finally{detecting=false;}}
        if(!closed&&ReadRoots().Length>0)await RunScan(true);
    }
    private async Task RunScan(bool automatic)
    {
        if(cts!=null || syncing || maintenance || detecting || closed || showingGuide) return;
        var roots=ReadRoots(); if(roots.Length==0) { GlassMessage.Show(this,"请先选择扫描目录。","提示"); return; }
        if(!automatic){ CaptureProfile(); try{PersistProfile();}catch(Exception ex){StartupLog.Write("Profile save failed: "+ex);} report=null; Results.ItemsSource=null; Details.Clear(); RefreshTiles(); }
        Counts.Text=automatic?"正在检查更新":"正在扫描"; SetProgressState(true,0);
        var rootKey=string.Join("\n",roots.OrderBy(x=>x,StringComparer.OrdinalIgnoreCase));
        if(rootKey!=baselineRoots){baseline=null;baselineRoots=rootKey;changes.Clear();LoadBaseline(rootKey);}
        bool fetchNames=TitleBox.IsChecked==true; var yaraSnapshot=yara; bool useAmsi=AmsiBox.IsChecked==true;
        var force=ForceBox.IsChecked==true; cts=new CancellationTokenSource(); var token=cts.Token;
        RecommendedBtn.IsEnabled=ScanBtn.IsEnabled=DetectBtn.IsEnabled=AddBtn.IsEnabled=RootsBox.IsEnabled=ForceBox.IsEnabled=ExportBtn.IsEnabled=QuickYaraBtn.IsEnabled=YaraBtn.IsEnabled=SyncBtn.IsEnabled=TitleBox.IsEnabled=AmsiBox.IsEnabled=false; CancelBtn.IsEnabled=true; UpdateEmptyState();
        var progress=new Progress<ScanProgress>(p=>{ if(closed||cts==null||cts.Token!=token)return; SetProgressState(true,p.Total==0?0:100.0*p.Done/p.Total); Status.Text=$"{p.Done}/{p.Total}  {p.File}"; });
        try
        {
            var next=await Task.Run(()=>new Scanner().Scan(roots,force&&!automatic,progress,token,yaraSnapshot,useAmsi));
            next=AssociateGames(next);
            if(fetchNames)
            {
                Status.Text="正在查询 Steam 工坊标题…";
                // Reuse names in automatic scans; query new IDs, or manually refresh all.
                if(automatic && baseline!=null)
                {
                    var known=baseline.Values.Where(r=>r.NameSource=="Steam 工坊" && r.WorkshopId.Length>0).GroupBy(r=>r.WorkshopId).ToDictionary(g=>g.Key,g=>g.First().Mod);
                    var remaining=next with {Files=next.Files.Where(r=>!known.ContainsKey(r.WorkshopId)).ToList()};
                    remaining=await WorkshopNames.ResolveAsync(remaining,token);
                    var fresh=remaining.Files.ToDictionary(r=>r.Path,StringComparer.OrdinalIgnoreCase);
                    next=next with {Files=next.Files.Select(r=>known.TryGetValue(r.WorkshopId,out var title)?r with {Mod=title,NameSource="Steam 工坊"}:fresh[r.Path]).ToList()};
                }
                else next=await WorkshopNames.ResolveAsync(next,token);
            }
            var old=baseline;
            var rows=next.Files.Select(r=>{
                string change="基线";
                if(old!=null){if(!old.TryGetValue(r.Path,out var prev))change="新增";else if(r.Sha256.Length==0||prev.Sha256.Length==0)change="未确认";else if(r.Sha256!=prev.Sha256)change="已更新";else change=automatic?prev.Change:"未变化";}
                if((change is "新增" or "已更新") && (old==null||!old.TryGetValue(r.Path,out var prior)||prior.Sha256!=r.Sha256))RecordChange(change,r);
                return r with {Change=change};
            }).ToList();
            var current=rows.ToDictionary(r=>r.Path,StringComparer.OrdinalIgnoreCase);
            // An incomplete scan does not establish removal.
            if(old!=null && !next.Warnings.Any(w=>w.StartsWith("目录未完整扫描")||w.StartsWith("目录不存在")||w.StartsWith("无效目录")||w.StartsWith("跳过重解析点目录")))foreach(var prev in old.Values.Where(r=>!current.ContainsKey(r.Path)))RecordChange("未再发现",prev);
            if(!next.Warnings.Any(w=>w.StartsWith("目录未完整扫描")||w.StartsWith("目录不存在")||w.StartsWith("无效目录")||w.StartsWith("跳过重解析点目录"))){baseline=current;await SaveBaseline(rootKey);}
            report=next with {Files=rows};
            RememberRiskHistory(rows);
            ApplyFilter(); RefreshTiles(); var f=report.Files;
            Counts.Text=$"文件 {f.Count}  |  极高 {f.Count(x=>x.Analysis.Risk==Risk.Critical)}  |  高 {f.Count(x=>x.Analysis.Risk==Risk.High)}  |  复核 {f.Count(x=>x.Analysis.Risk==Risk.Review)}  |  未知 {f.Count(x=>x.Analysis.Risk==Risk.Unknown)}  |  未发现 {f.Count(x=>x.Analysis.Risk==Risk.Clear)}";
            SetProgressState(false); Status.Text=f.Count==0?"未找到待扫描文件；请检查目录。":$"扫描完成，缓存命中 {f.Count(x=>x.Cached)}，下载线索 {f.Count(x=>x.DownloadLabel is "直接文件下载 API" or "疑似下载落盘" or "联网+写入（待核实）")}，警告 {report.Warnings.Count} 条。未发现风险不代表安全。";
            ExportBtn.IsEnabled=true;
        }
        catch(OperationCanceledException) { report=null;Results.ItemsSource=null;RefreshTiles();Counts.Text="已取消"; Status.Text="本次扫描未完成，不能据此判断安全。"; SetProgressState(false); }
        catch(Exception ex) { report=null;Results.ItemsSource=null;RefreshTiles();StartupLog.Write("Scan failed: "+ex); Counts.Text="扫描失败"; Status.Text=ex.Message; SetProgressState(false); }
        finally { cts.Dispose(); cts=null; if(!closed) { SetProgressState(false); UpdateEmptyState(); RecommendedBtn.IsEnabled=ScanBtn.IsEnabled=AddBtn.IsEnabled=RootsBox.IsEnabled=ForceBox.IsEnabled=true; DetectBtn.IsEnabled=!detecting; CancelBtn.IsEnabled=false; QuickYaraBtn.IsEnabled=YaraBtn.IsEnabled=SyncBtn.IsEnabled=TitleBox.IsEnabled=AmsiBox.IsEnabled=true; ExportBtn.IsEnabled=report!=null; } }
    }
    private void Cancel_Click(object sender,RoutedEventArgs e) => cts?.Cancel();
    private void Filter_Changed(object sender,SelectionChangedEventArgs e) { UpdateTileSelection(); if(report!=null) ApplyFilter(); }
    private void ApplyFilter()
    {
        if(report==null) return; var label=(FilterBox.SelectedItem as ComboBoxItem)?.Content as string;var prior=(Results.SelectedItem as ScanRow)?.Path;
        Results.ItemsSource=report.Files.Where(r=>label switch {null or "全部"=>true,"防病毒引擎检出"=>r.AmsiLabel is "引擎检出恶意内容" or "引擎策略阻止" or "引擎返回风险值","内部可执行内容"=>r.Analysis.Evidence.Any(e=>e.Rule is "内部可执行内容" or "资源扩展名中的 PE 文件"),"高危及极高风险"=>r.Analysis.Risk is Risk.High or Risk.Critical,"直接/疑似文件下载"=>r.DownloadLabel is "直接文件下载 API" or "疑似下载落盘" or "联网+写入（待核实）","有网络行为"=>r.DownloadLabel is not ("未发现" or "未知（未完成）"),"新增/更新"=>r.Change is "新增" or "已更新","共享 IL 指纹"=>r.Similarity!="—","含域名线索"=>r.Analysis.Hosts?.Count>0,"原生 PE"=>r.Analysis.Kind is "原生 PE" or "混合模式 PE","脚本"=>r.Analysis.Kind.StartsWith("脚本"),_=>r.RiskLabel==label}).Where(r=>string.IsNullOrWhiteSpace(SearchBox?.Text)||new[]{r.Mod,r.GameName,r.FileName,r.Path,r.Sha256,r.WorkshopId,r.AppId,r.HostLabel}.Concat(r.Analysis.Hosts??[]).Any(v=>v.Contains(SearchBox.Text.Trim(),StringComparison.OrdinalIgnoreCase))).OrderByDescending(r=>r.Analysis.Risk switch {Risk.Critical=>5,Risk.High=>4,Risk.Unknown=>3,Risk.Review=>2,_=>1}).ThenBy(r=>r.Mod).ToList();
        if(prior!=null&&Results.ItemsSource is List<ScanRow> visible)Results.SelectedItem=visible.FirstOrDefault(r=>r.Path.Equals(prior,StringComparison.OrdinalIgnoreCase));
        if(Results.SelectedItem==null&&Results.Items.Count>0)Results.SelectedIndex=0;UpdateEmptyState();
    }
    private void Results_Changed(object sender,SelectionChangedEventArgs e)
    {
        if(Details==null) return;
        if(Results.SelectedItem is not ScanRow r) { Details.Clear(); UpdateSelection(null); return; }
        UpdateSelection(r);
        var b=new StringBuilder(); b.AppendLine($"{r.RiskLabel} | {r.Analysis.Kind} | {r.Size:N0} bytes"); b.AppendLine($"游戏: {r.GameName} [{r.AppId}] | Mod: {r.Mod} | {r.NameSource} | ID: {r.WorkshopId} | {r.Change}"); b.AppendLine($"下载行为：{r.DownloadLabel} | YARA：{r.YaraLabel} | AMSI：{r.AmsiLabel} | 同类线索：{r.Similarity}"); b.AppendLine("静态域名线索（不主动访问）: "+(r.Analysis.Hosts?.Count>0?string.Join(", ",r.Analysis.Hosts):"未发现")); b.AppendLine(r.Path); b.AppendLine("SHA-256: "+(r.Sha256.Length==0?"未计算":r.Sha256)); if(r.Analysis.Error!=null)b.AppendLine(r.Analysis.Error);
        foreach(var ev in r.Analysis.Evidence) b.AppendLine($"[{ev.Risk}] {ev.Rule}\n  {ev.Method}\n  {ev.Detail}");
        if(r.Analysis.Fingerprints?.Count>0)b.AppendLine("\n归一化 IL 方法指纹 (il-v1):\n"+string.Join("\n",r.Analysis.Fingerprints));
        Details.Text=b.ToString();
    }
    private void Export_Click(object sender,RoutedEventArgs e)
    {
        if(report==null)return; var dlg=new SaveFileDialog { Filter="JSON 报告|*.json", FileName=$"guardian-{DateTime.Now:yyyyMMdd-HHmmss}.json" }; if(dlg.ShowDialog(this)!=true)return;
        try{Scanner.Export(report,dlg.FileName);Status.Text="报告已导出："+dlg.FileName;}catch(Exception ex){GlassMessage.Show(this,ex.Message);}
    }
    private void Blacklist_Click(object sender,RoutedEventArgs e) { if(maintenance)return; try { Scanner.EnsureData(); Process.Start(new ProcessStartInfo("notepad.exe", "\""+Scanner.BlacklistPath+"\""){UseShellExecute=false}); } catch(Exception ex){GlassMessage.Show(this,ex.Message);} }
    private void Workshop_Click(object sender,RoutedEventArgs e) { if(Results.SelectedItem is ScanRow r && ulong.TryParse(r.WorkshopId,out var id)) { try { Process.Start(new ProcessStartInfo($"https://steamcommunity.com/sharedfiles/filedetails/?id={id}"){UseShellExecute=true}); }catch(Exception ex){GlassMessage.Show(this,ex.Message);} } else GlassMessage.Show(this,"该文件没有可识别的工坊 ID。"); }
    private void CopyHash_Click(object sender,RoutedEventArgs e) { if(Results.SelectedItem is ScanRow r && r.Sha256.Length>0) try { Clipboard.SetText(r.Sha256);Status.Text="SHA-256 已复制"; } catch(Exception ex){GlassMessage.Show(this,ex.Message);} }
    private void Warnings_Click(object sender,RoutedEventArgs e) { Details.Text=report==null?"尚未扫描。":report.Warnings.Count==0?"没有目录或缓存警告。":string.Join(Environment.NewLine,report.Warnings); }
    private void RecordChange(string kind,ScanRow row)
    {
        var line=$"{DateTimeOffset.Now:O} {kind} | {row.Mod} | {row.WorkshopId} | {row.Path} | {row.Sha256}";
        changes.Add(line); if(changes.Count>2000)changes.RemoveAt(0);
    }
    private void History_Click(object sender,RoutedEventArgs e) => Details.Text=changes.Count==0?"当前扫描范围无持久化变化记录。":string.Join(Environment.NewLine,changes.TakeLast(500).Reverse());
    private void Config_Click(object sender,RoutedEventArgs e)
    {
        try{Scanner.EnsureData();Process.Start(new ProcessStartInfo(Scanner.DataDir){UseShellExecute=true});}catch(Exception ex){GlassMessage.Show(this,ex.Message);}
    }
    private async void Yara_Click(object sender,RoutedEventArgs e)
    {
        if(Busy)return;
        if(yara!=null){if(GlassMessage.Show(this,"是否关闭当前 YARA 检测？关闭后静态检测仍然可用。","YARA",MessageBoxButton.OKCancel)!=MessageBoxResult.OK)return;yara=null;YaraText.Text="YARA 未启用";InvalidateReport();return;}
        if(GlassMessage.Show(this,"1. 在 github.com/VirusTotal/yara/releases 下载 Windows x64 压缩包。\n2. 解压到独立可信目录，例如 C:\\Tools\\YARA。\n3. 选择 yara64.exe（不是 yarac64.exe）。\n4. 推荐使用软件附带的 guardian.yar 规则。\n\n只运行你信任的 YARA 程序和规则，不要选择模组内的文件。接下来会用无害文本进行配置测试。","YARA 配置向导",MessageBoxButton.OKCancel,MessageBoxImage.Warning)!=MessageBoxResult.OK)return;
        // Guard the native picker interval too: no timer or scan starts during configuration.
        SetMaintenance(true);
        try
        {
            var exe=new OpenFileDialog{Title="第 1 步：选择可信 yara64.exe",Filter="YARA 程序|yara64.exe;yara.exe|EXE|*.exe",CheckFileExists=true};if(exe.ShowDialog(this)!=true)return;
            var bundled=Path.Combine(AppContext.BaseDirectory,"rules","guardian.yar");
            string rulePath;
            if(File.Exists(bundled)&&GlassMessage.Show(this,"使用随软件提供的 guardian.yar 推荐规则？\n\n确认：使用内置规则。\n取消：手动选择其他可信 .yar 规则。","第 2 步：选择规则",MessageBoxButton.OKCancel)!=MessageBoxResult.Cancel)rulePath=bundled;
            else {var rule=new OpenFileDialog{Title="第 2 步：选择可信 YARA 源规则",Filter="YARA|*.yar;*.yara",InitialDirectory=Path.GetDirectoryName(bundled)!,CheckFileExists=true};if(rule.ShowDialog(this)!=true)return;rulePath=rule.FileName;}
            var candidate=new YaraScan(exe.FileName,rulePath);
            if(ReadRoots().Concat(catalog.SelectMany(g=>g.Roots)).Any(r=>candidate.IsInside(r)))throw new IOException("不能从模组扫描目录中选择 YARA 程序或规则。请使用独立可信目录。");
            YaraText.Text="正在测试 YARA 程序及规则…";
            var tested=await Task.Run(()=>candidate.Apply(Encoding.UTF8.GetBytes("Steam Mod Guardian harmless configuration test"),new Analysis(Risk.Clear,"配置测试",[]),CancellationToken.None));
            if(closed)return;
            if(tested.YaraStatus.StartsWith("失败："))throw new IOException(tested.YaraStatus);
            yara=candidate;InvalidateReport();YaraText.Text="YARA 已启用 · 配置测试通过（再次点击关闭）";Status.Text="YARA 程序和规则测试通过。下次扫描将使用 YARA；测试不代表病毒检出能力已验证。";
        }
        catch(Exception ex){if(!closed){YaraText.Text="YARA 未启用：配置测试失败";StartupLog.Write("YARA configuration failed: "+ex);GlassMessage.Show(this,ex.Message+"\n\n请检查是否选择了 yara64.exe、压缩包是否完整解压、规则是否兼容。","YARA 配置失败",MessageBoxButton.OK,MessageBoxImage.Warning);}}
        finally{if(!closed)SetMaintenance(false);}
    }
    private async void Sync_Click(object sender,RoutedEventArgs e)
    {
        if(syncing||cts!=null||maintenance)return;
        if(GlassMessage.Show(this,"请先在配置目录设置 community-url.txt 和经独立验证的 community-public.pem。仅同步你信任的 HTTPS 名单；不会上传模组。","同步社区名单",MessageBoxButton.OKCancel)!=MessageBoxResult.OK)return;
        syncing=true;SyncBtn.IsEnabled=ScanBtn.IsEnabled=false;
        try{var v=await Community.SyncAsync(CancellationToken.None);if(!closed)Status.Text=$"社区名单 v{v} 已同步，请重新扫描。";}
        catch(Exception ex){if(!closed)GlassMessage.Show(this,"同步失败："+ex.Message);}
        finally{syncing=false;if(!closed)SyncBtn.IsEnabled=ScanBtn.IsEnabled=true;}
    }
    private void Evidence_Click(object sender,RoutedEventArgs e)
    {
        if(report==null||Results.SelectedItem is not ScanRow r)return;
        var files=report.Files.Where(x=>r.WorkshopId.Length>0?x.WorkshopId==r.WorkshopId:x.Path==r.Path).Select(x=>new{ x.GameName,x.AppId,x.Mod,x.NameSource,x.WorkshopId,File=Path.GetFileName(x.Path),x.Sha256,x.Size,x.RiskLabel,x.Analysis,x.Change,x.Similarity }).ToList();
        var dlg=new SaveFileDialog{Filter="JSON|*.json",FileName="guardian-evidence-"+(r.WorkshopId.Length>0?r.WorkshopId:DateTime.Now.ToString("yyyyMMddHHmmss"))+".json"};if(dlg.ShowDialog(this)!=true)return;
        try{File.WriteAllText(dlg.FileName,System.Text.Json.JsonSerializer.Serialize(new{report.Time,report.RuleVersion,WorkshopUrl=r.WorkshopId.Length>0?"https://steamcommunity.com/sharedfiles/filedetails/?id="+r.WorkshopId:"",Notice="静态线索，不是恶意定论；人工复核后举报；请检查证据是否含隐私。",Files=files},new System.Text.Json.JsonSerializerOptions{WriteIndented=true}));Status.Text="举报证据已导出，复核后手动提交。";}catch(Exception ex){GlassMessage.Show(this,ex.Message);}
    }

    private void SetProgressState(bool active,double value=0)
    {
        if(Progress==null)return;
        TaskProgressPanel.Visibility=active?Visibility.Visible:Visibility.Collapsed;
        Progress.IsIndeterminate=false; Progress.Value=Math.Clamp(value,0,100);
        TaskProgressLabel.Text=$"检查进度  {Progress.Value:0}%";
    }

    protected override void OnClosed(EventArgs e) { closed=true; monitor.Stop(); runtimeWindow?.Close(); quickYaraCancellation?.Cancel(); cts?.Cancel(); StartupLog.Write("Window closed"); base.OnClosed(e); }
}
