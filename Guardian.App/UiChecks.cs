using Guardian.Core;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Threading;
namespace Guardian.App;
public partial class MainWindow
{
    // Uses synthetic rows only; never reads or executes mod files and never contacts the network.
    internal async Task RunUiChecksAsync()
    {
        static void Check(bool ok,string label){if(!ok)throw new InvalidOperationException("UI smoke test: "+label);}
        Check(WindowStyle==WindowStyle.None,"window chrome");
        Check(AcrylicSurface.CornerRadius.TopLeft>=20,"rounded surface");
        Check(AmsiBox.IsChecked==false,"AMSI opt-in default");
        Check(QuickYaraBtn.IsEnabled&&QuickYaraBtn.Visibility==Visibility.Visible,"quick YARA available");
        Check(AcrylicSurface.BorderThickness==new Thickness(0),"no main outer stroke");
        FilterBox.ApplyTemplate();
        var toggle=FilterBox.Template.FindName("DropToggle",FilterBox) as ToggleButton;
        var popup=FilterBox.Template.FindName("PART_Popup",FilterBox) as Popup;
        Check(toggle!=null&&popup!=null,"dropdown template parts");
        toggle!.SetCurrentValue(ToggleButton.IsCheckedProperty,true);
        await Dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);
        Check(FilterBox.IsDropDownOpen&&popup!.IsOpen,"dropdown toggle binding");
        FilterBox.IsDropDownOpen=false;
        Check(TileAllButton.Tag as string=="active","initial tile selected");
        Check(MinimizeButton.Content is System.Windows.Controls.Viewbox,"vector title icon");
        Check(TaskProgressPanel.Visibility==Visibility.Collapsed,"idle progress hidden");
        SetProgressState(true,25);Check(TaskProgressPanel.Visibility==Visibility.Visible&&TaskProgressLabel.Text.Contains("25%"),"percent progress");SetProgressState(false);
        var a=new ScanRow("Synthetic A","","a.dll","",0,DownloadRiskPolicy.Apply(new Analysis(Risk.Review,"测试",[],Download:"直接文件下载 API")),false);
        var b=new ScanRow("Synthetic B","","b.dll","",0,new Analysis(Risk.Clear,"测试",[]),false);
        var unknown=new ScanRow("Synthetic C","","c.dll","",0,new Analysis(Risk.Unknown,"测试",[]),false);
        report=new ScanReport(DateTimeOffset.Now,"ui-smoke",[],[a,b,unknown],[]);ApplyFilter();RefreshTiles();
        Check(Results.Items.Count==3&&Results.IsReadOnly&&EmptyPanel.Visibility==Visibility.Collapsed,"result list");
        TileRiskButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Check(TileRiskButton.Tag as string=="active","risk tile selected");Check(Results.Items.Count==1&&RiskExplanation.Text.Contains("高风险"),"high risk filter and explanation");
        TileDownloadButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Check(TileDownloadButton.Tag as string=="active","download tile selected");Check(Results.Items.Count==1,"download filter");
        TileUnknownButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Check(Results.Items.Count==1&&TileUnknownButton.Tag as string=="active","unknown tile selected");
        SearchBox.Text="no_match_123";Check(Results.Items.Count==0&&EmptyPanel.Visibility==Visibility.Visible,"empty state");
        TileAllButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Check(Results.Items.Count==3&&TileAllButton.Tag as string=="active","all tile and search reset");
        var dialog=new GlassWindow(this,"UI smoke test",480,360);
        var stack=new StackPanel();var bar=new ScrollBar{Orientation=Orientation.Horizontal,Minimum=0,Maximum=100,ViewportSize=20};stack.Children.Add(bar);stack.Children.Add(new PasswordBox());stack.Children.Add(new Button{Content="test"});dialog.SetBody(stack);
        try{dialog.Show();await Dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);bar.ApplyTemplate();var track=bar.Template.FindName("PART_Track",bar) as Track;Check(track?.Orientation==Orientation.Horizontal&&track.IsDirectionReversed==false,"horizontal scroll track");Check(dialog.IsVisible&&dialog.WindowStyle==WindowStyle.None,"custom dialog");Check(dialog.Content is Border frame&&frame.BorderThickness==new Thickness(0),"no dialog outer stroke");}
        finally{dialog.Close();}
    }
}
