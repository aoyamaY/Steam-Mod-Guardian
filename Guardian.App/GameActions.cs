using Guardian.Core;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
namespace Guardian.App;
public partial class MainWindow
{
    private List<SteamGame> catalog=[];
    private readonly HashSet<string> selectedIds=new();
    private bool maintenance;
    private bool Busy=>maintenance||cts!=null||syncing||detecting||closed||GlassWindow.ModalDepth>0;
    private void UpdateGameLabel()=>GameLabel.Text=$"已识别 {catalog.Count} 个游戏 · 已选择 {selectedIds.Count} 个";
    private void SetGames(IEnumerable<SteamGame> games)
    {
        CaptureProfile();var chosen=games.ToList();selectedIds.Clear();foreach(var g in chosen)selectedIds.Add(g.AppId);
        RootsBox.Text=string.Join(Environment.NewLine,ProfileStore.RootsFor(chosen,extraRoots,unassignedRoots));
        UpdateGameLabel();InvalidateReport();try{PersistProfile();}catch(Exception ex){StartupLog.Write("Profile save failed: "+ex);}Status.Text=$"扫描范围已替换；{chosen.Count(g=>g.Roots.Count==0)} 个所选游戏无自动识别模组目录，需手动添加。";
    }
    private void InvalidateReport(){report=null;Results.ItemsSource=null;Details.Clear();ExportBtn.IsEnabled=false;Counts.Text="需要重新扫描";baseline=null;baselineRoots="";RefreshTiles();}
    private bool ConfirmReplace()=>ReadRoots().Length==0||GlassMessage.Show(this,"选择游戏将切换扫描范围。单选游戏的额外目录会随该游戏保存；未关联目录会保留。继续？","扫描范围",MessageBoxButton.OKCancel,MessageBoxImage.Question)==MessageBoxResult.OK;
    private void Games_Click(object sender,RoutedEventArgs e)
    {
        if(Busy)return;if(catalog.Count==0){GlassMessage.Show(this,"请先刷新 Steam 游戏库，或在高级设置中手动添加模组目录。");return;}
        catalog=WithGameNames(catalog);var dialog=new GlassWindow(this,"选择需要检查的 Steam 游戏",820,700);
        var panel=new DockPanel{Margin=new Thickness(8)};var top=new StackPanel();DockPanel.SetDock(top,Dock.Top);panel.Children.Add(top);
        top.Children.Add(new TextBlock{Text="选择一个或多个游戏。没有已知目录的游戏需要手动配置。",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,0,0,8)});
        top.Children.Add(new TextBlock{Text="搜索中文名、原名、目录名或 AppID",Foreground=dialog.Brush("SubtleBrush")});var search=new TextBox{Margin=new Thickness(0,4,0,8)};top.Children.Add(search);
        var filter=new ComboBox{ItemsSource=new[]{"有已知模组目录","全部游戏","已安装","曾发现高危（本工具记录）"},SelectedIndex=0,Margin=new Thickness(0,0,0,8)};top.Children.Add(filter);
        var online=new Button{Content="获取当前列表中文名称（最多 50 个）"};top.Children.Add(online);var count=new TextBlock{Margin=new Thickness(0,4,0,8)};top.Children.Add(count);var note=new TextBlock{TextWrapping=TextWrapping.Wrap,Foreground=dialog.Brush("SubtleBrush"),Margin=new Thickness(0,0,0,8)};top.Children.Add(note);
        var buttons=new WrapPanel{Margin=new Thickness(0,8,0,0)};DockPanel.SetDock(buttons,Dock.Bottom);panel.Children.Add(buttons);
        var chosen=new HashSet<string>(selectedIds);var list=new StackPanel();panel.Children.Add(new ScrollViewer{Content=list,VerticalScrollBarVisibility=ScrollBarVisibility.Auto});
        bool HasRoot(SteamGame g)=>g.Roots.Count>0||extraRoots.TryGetValue(g.AppId,out var extra)&&extra.Count>0;
        List<SteamGame> Visible()=>catalog.Where(g=>(filter.SelectedIndex switch {0=>HasRoot(g),2=>g.Installed,3=>RiskHistory().Contains(g.AppId),_=>true})&&(g.Label+" "+g.AltName).Contains(search.Text.Trim(),StringComparison.OrdinalIgnoreCase)).OrderBy(g=>g.DisplayName,StringComparer.CurrentCultureIgnoreCase).ToList();
        void Count()=>count.Text=$"已选择 {chosen.Count} / {catalog.Count} · 当前显示 {Visible().Count} 个";
        void Render(){list.Children.Clear();var games=Visible();foreach(var group in games.GroupBy(g=>g.Installed?"已安装":"仅工坊内容").OrderBy(g=>g.Key=="已安装"?0:1)){list.Children.Add(new TextBlock{Text=group.Key+" · "+group.Count(),FontWeight=FontWeights.SemiBold,Foreground=dialog.Brush("SubtleBrush"),Margin=new Thickness(4,8,0,6)});foreach(var g in group){var card=new Border{Style=(Style)dialog.FindResource("GlassBorderStyle"),Padding=new Thickness(12,8,12,8),Margin=new Thickness(0,0,5,6)};var stack=new StackPanel();var cb=new CheckBox{Content=g.DisplayName,IsChecked=chosen.Contains(g.AppId),FontSize=15,FontWeight=FontWeights.SemiBold};cb.Checked+=(_,_)=>{chosen.Add(g.AppId);Count();};cb.Unchecked+=(_,_)=>{chosen.Remove(g.AppId);Count();};stack.Children.Add(cb);stack.Children.Add(new TextBlock{Text=$"AppID {g.AppId} · {(HasRoot(g)?"已有模组目录":"需要手动配置")}"+(RiskHistory().Contains(g.AppId)?" · 曾发现高危":"")+(string.IsNullOrWhiteSpace(g.AltName)||g.Name==g.AltName?"":$" · 安装目录名：{g.AltName}"),Foreground=dialog.Brush("SubtleBrush"),Margin=new Thickness(26,3,0,0),TextWrapping=TextWrapping.Wrap});card.Child=stack;list.Children.Add(card);}}if(games.Count==0)list.Children.Add(new TextBlock{Text="没有匹配游戏。尝试切换筛选或修改搜索词。",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(10)});Count();}
        search.TextChanged+=(_,_)=>Render();filter.SelectionChanged+=(_,_)=>Render();Render();
        using var cancel=new CancellationTokenSource();bool ended=false;dialog.Closed+=(_,_)=>{ended=true;cancel.Cancel();};
        online.Click+=async(_,_)=>{var ids=Visible().Where(g=>!GameNames().ContainsKey(g.AppId)).Select(g=>g.AppId).Take(50).ToList();if(ids.Count==0){note.Text="当前游戏已有缓存，或没有可查询的游戏。";return;}if(GlassMessage.Show(dialog,$"向 Steam 商店发送 {ids.Count} 个游戏 AppID，获取简体中文商店名称。不发送模组或账号信息。继续？","获取中文名称",MessageBoxButton.OKCancel)!=MessageBoxResult.OK)return;online.IsEnabled=false;try{int n=await FetchGameNamesAsync(ids,cancel.Token,v=>{if(!ended)note.Text=v;});if(!ended){catalog=WithGameNames(catalog);Render();note.Text=$"取得 {n} 个名称；未取得的保留本地名称。";}}catch(OperationCanceledException){}catch(Exception ex){if(!ended)note.Text="查询失败："+ex.Message;}finally{if(!ended)online.IsEnabled=true;}};
        void B(string text,Action action,bool primary=false){var b=dialog.ActionButton(text,primary);b.Click+=(_,_)=>action();buttons.Children.Add(b);}
        B("选择当前显示",()=>{foreach(var g in Visible())chosen.Add(g.AppId);Render();});B("清空选择",()=>{chosen.Clear();Render();});B("应用选择",()=>dialog.DialogResult=true,true);B("取消",()=>dialog.DialogResult=false);dialog.SetBody(panel);
        if(dialog.ShowModal()==true&&ConfirmReplace())SetGames(catalog.Where(g=>chosen.Contains(g.AppId)));
    }
    private void AllGames_Click(object sender,RoutedEventArgs e){if(!Busy&&catalog.Count>0&&ConfirmReplace())SetGames(catalog);}
    private ScanReport AssociateGames(ScanReport scan)
    {
        return scan with {Files=scan.Files.Select(r=>{
            var g=catalog.FirstOrDefault(x=>x.AppId==r.AppId) ?? catalog.Where(x=>x.Roots.Any(root=>Quarantine.Inside(r.Path,root))).FirstOrDefault();
            if(g==null&&r.AppId.Length==0){var matches=catalog.Where(x=>selectedIds.Contains(x.AppId)&&extraRoots.TryGetValue(x.AppId,out var extra)&&extra.Any(root=>Quarantine.Inside(r.Path,root))).ToList();if(matches.Count==1)g=matches[0];else if(matches.Count==0&&selectedIds.Count==1&&!unassignedRoots.Any(root=>Quarantine.Inside(r.Path,root)))g=catalog.FirstOrDefault(x=>selectedIds.Contains(x.AppId));}
            return r with {AppId=g?.AppId??r.AppId,GameName=g?.DisplayName??(r.AppId.Length>0?"App "+r.AppId:"未关联游戏")};
        }).ToList()};
    }
    private void SetMaintenance(bool value)
    {
        maintenance=value;RecommendedBtn.IsEnabled=RootsBox.IsEnabled=ScanBtn.IsEnabled=AddBtn.IsEnabled=DetectBtn.IsEnabled=QuickYaraBtn.IsEnabled=YaraBtn.IsEnabled=SyncBtn.IsEnabled=TitleBox.IsEnabled=AmsiBox.IsEnabled=!value;
    }
    private async void Quarantine_Click(object sender,RoutedEventArgs e)
    {
        if(Busy||report==null||Results.SelectedItem is not ScanRow row)return;
        if(row.Analysis.Risk is not (Risk.High or Risk.Critical)||row.Sha256.Length==0){GlassMessage.Show(this,"请选择已完成哈希计算的高危或极高危文件。");return;}
        if(GlassMessage.Show(this,$"先退出游戏并暂停 Steam 更新。\n\n将移动以下文件到隔离库，不是删除整个 Mod：\n{row.GameName} / {row.Mod}\n{row.Path}\n\n高风险不等于恶意。隔离可能使 Mod 失效，Steam 也可能重新下载。请确认不是游戏本体文件。","确认隔离",MessageBoxButton.OKCancel,MessageBoxImage.Warning)!=MessageBoxResult.OK)return;
        var roots=report.Roots.ToArray();SetMaintenance(true);
        try{var entry=await Task.Run(()=>Quarantine.Move(row,roots));if(!closed){InvalidateReport();Status.Text="已隔离："+entry.Id+"；请重新扫描。";}}
        catch(Exception ex){if(!closed){InvalidateReport();GlassMessage.Show(this,"隔离未确认完成："+ex.Message+"\n请检查隔离库和原目录，重新扫描。","隔离",MessageBoxButton.OK,MessageBoxImage.Warning);}}
        finally{if(!closed)SetMaintenance(false);}
    }
    private async void Vault_Click(object sender,RoutedEventArgs e)
    {
        if(Busy)return;SetMaintenance(true);
        try
        {
            var entries=await Task.Run(()=>Quarantine.List());if(closed)return;
            if(entries.Count==0){GlassMessage.Show(this,"隔离库中没有可恢复记录。");return;}
            var dialog=new GlassWindow(this,"隔离库 · 恢复文件",850,510);
            var panel=new DockPanel{Margin=new Thickness(12)};var hint=new TextBlock{Text="仅在确认误报后恢复。恢复可能重新引入恶意代码。",TextWrapping=TextWrapping.Wrap,Foreground=dialog.Brush("WarnBrush"),Margin=new Thickness(0,0,0,10)};DockPanel.SetDock(hint,Dock.Top);panel.Children.Add(hint);var restore=new Button{Content="恢复所选文件（不覆盖）",IsEnabled=false,Margin=new Thickness(0,8,0,0),Padding=new Thickness(12,6,12,6)};DockPanel.SetDock(restore,Dock.Bottom);panel.Children.Add(restore);
            var list=new ListBox{ItemsSource=entries.Select(x=>$"{x.Time:g} | {x.Game} | {x.Mod} | {x.OriginalPath}").ToList()};panel.Children.Add(list);list.SelectionChanged+=(_,_)=>restore.IsEnabled=list.SelectedIndex>=0;restore.Click+=(_,_)=>{if(list.SelectedIndex>=0)dialog.DialogResult=true;};dialog.SetBody(panel);
            if(dialog.ShowModal()!=true)return;var entry=entries[list.SelectedIndex];
            if(GlassMessage.Show(this,$"恢复可能重新引入恶意代码，只有确认误报时才恢复。\n{entry.OriginalPath}\nSHA-256: {entry.Sha256}\n请退出游戏并暂停 Steam 更新。","确认恢复",MessageBoxButton.OKCancel,MessageBoxImage.Warning)!=MessageBoxResult.OK)return;
            await Task.Run(()=>Quarantine.Restore(entry));if(!closed){InvalidateReport();Status.Text="文件已恢复，请重新扫描。";}
        }
        catch(Exception ex){if(!closed){InvalidateReport();GlassMessage.Show(this,ex.Message);}}
        finally{if(!closed)SetMaintenance(false);}
    }
    private async void Launch_Click(object sender,RoutedEventArgs e)
    {
        if(Busy)return;
        if(selectedIds.Count!=1){GlassMessage.Show(this,"请先仅选择一个要启动的 Steam 游戏，并添加该游戏其他本地 Mod 目录。");return;}
        var id=selectedIds.Single();var game=catalog.FirstOrDefault(x=>x.AppId==id);
        if(game==null||!game.Installed){GlassMessage.Show(this,"没有识别到已安装的游戏，无法通过安全检查启动。");return;}
        if(GlassMessage.Show(this,$"对 {game.Name} 重新识别工坊目录，并完整复查当前配置的扫描目录。\n\n请确认已加入该游戏全部其他本地 Mod 目录，已退出游戏并暂停 Steam 更新。此功能不是沙箱，不拦截直接启动，也无法保证启动后文件不变化。","启动前复查",MessageBoxButton.OKCancel,MessageBoxImage.Warning)!=MessageBoxResult.OK)return;
        var manual=ReadRoots();var engine=yara;bool useAmsi=AmsiBox.IsChecked==true;SetMaintenance(true);Counts.Text="启动前复查";
        try
        {
            var fresh=await Task.Run(SteamPaths.Detect);if(closed)return;
            var target=fresh.FirstOrDefault(x=>x.AppId==id&&x.Installed)??throw new IOException("未重新识别到已安装游戏。");
            catalog=WithGameNames(fresh);var roots=manual.Concat(target.Roots).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();if(roots.Length==0)throw new IOException("没有已配置模组目录；无法确认扫描范围，请添加目录。");
            RootsBox.Text=string.Join(Environment.NewLine,roots);
            cts=new CancellationTokenSource();var token=cts.Token;CancelBtn.IsEnabled=true;
            SetProgressState(true,0); var progress=new Progress<ScanProgress>(p=>{if(closed||cts==null||cts.Token!=token)return;SetProgressState(true,p.Total==0?0:100.0*p.Done/p.Total);Status.Text=$"启动前复查 {p.Done}/{p.Total}";});
            var next=await Task.Run(()=>new Scanner().Scan(roots,true,progress,token,engine,useAmsi));if(closed)return;
            report=AssociateGames(next);RememberRiskHistory(report.Files);ApplyFilter();RefreshTiles();ExportBtn.IsEnabled=true;var files=report.Files;
            int block=files.Count(x=>x.Analysis.Risk is Risk.High or Risk.Critical or Risk.Unknown || x.YaraLabel.StartsWith("失败：") || x.AmsiLabel.StartsWith("失败："));
            int review=files.Count(x=>x.Analysis.Risk==Risk.Review);
            Counts.Text=$"启动前复查：{files.Count} 个文件，阻止项 {block}，需复核 {review}，警告 {report.Warnings.Count}";
            if(block>0||report.Warnings.Count>0){Status.Text="未通过启动检查；请查看风险和扫描警告。";GlassMessage.Show(this,"存在高危、未知或扫描警告，本工具不会启动游戏。请处理后重新检查。");return;}
            if(GlassMessage.Show(this,$"已复查 {files.Count} 个可扫描文件，需复核 {review} 个。请确认已人工核对可疑行为。未发现高危不代表安全；Steam 仍可能更新文件。\n\n继续启动 {target.Name}？","确认启动",MessageBoxButton.OKCancel,MessageBoxImage.Warning)!=MessageBoxResult.OK)return;
            // Recheck file identities immediately after the confirmation; never trust an old report.
            var finalCatalog=await Task.Run(SteamPaths.Detect);if(closed)return;
            var finalGame=finalCatalog.FirstOrDefault(g=>g.AppId==id&&g.Installed)??throw new IOException("游戏安装状态变化，请重新检查。");
            if(!target.Roots.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(finalGame.Roots))throw new IOException("工坊目录发生变化，请重新检查。");
            var final=await Task.Run(()=>new Scanner().Scan(roots,false,progress,token,engine,useAmsi));if(closed)return;
            token.ThrowIfCancellationRequested();
            if(final.Warnings.Count>0||final.Files.Any(r=>r.Analysis.Risk is Risk.High or Risk.Critical or Risk.Unknown || r.YaraLabel.StartsWith("失败：") || r.AmsiLabel.StartsWith("失败："))||!LaunchChecks.SameFiles(next,final))
            {report=AssociateGames(final);RememberRiskHistory(report.Files);ApplyFilter();RefreshTiles();Status.Text="复查发现变化，已取消启动。";GlassMessage.Show(this,"确认后文件、检测结果或扫描范围发生变化，请重新检查。");return;}
            Process.Start(new ProcessStartInfo("steam://rungameid/"+id){UseShellExecute=true});Status.Text="已向 Steam 请求启动；未提供持续加载拦截。";
        }
        catch(OperationCanceledException){if(!closed)Status.Text="启动前复查已取消，未启动游戏。";}
        catch(Exception ex){if(!closed){Status.Text="启动前复查失败";GlassMessage.Show(this,ex.Message);}}
        finally{cts?.Dispose();cts=null;if(!closed){SetProgressState(false);CancelBtn.IsEnabled=false;SetMaintenance(false);}}
    }
}
