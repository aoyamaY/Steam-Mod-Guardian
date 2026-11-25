using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shell;
namespace Guardian.App;

// App-owned dialogs share the main theme. Native file pickers and fatal fallback remain OS dialogs.
internal class GlassWindow : Window
{
    private readonly ContentControl body = new();
    internal static int ModalDepth { get; private set; }
    internal bool? ShowModal(){ModalDepth++;try{return ShowDialog();}finally{ModalDepth--;}}
    public GlassWindow(Window owner, string title, double width, double height, bool resizable = true)
    {
        Owner=owner; Title=title; Width=width; Height=height; MinWidth=Math.Min(width,460); MinHeight=Math.Min(height,300);
        WindowStartupLocation=WindowStartupLocation.CenterOwner; WindowStyle=WindowStyle.None;
        ResizeMode=resizable?ResizeMode.CanResize:ResizeMode.NoResize; ShowInTaskbar=false;
        FontFamily=owner.FontFamily; FontSize=owner.FontSize; Foreground=owner.Foreground; Background=new SolidColorBrush(Color.FromRgb(24,28,35));
        Resources.MergedDictionaries.Add(owner.Resources);
        WindowChrome.SetWindowChrome(this,new WindowChrome { CaptionHeight=0, GlassFrameThickness=new Thickness(0), ResizeBorderThickness=new Thickness(resizable?7:0), UseAeroCaptionButtons=false });
        var frame=new Border{Margin=new Thickness(0),BorderThickness=new Thickness(0),CornerRadius=new CornerRadius(22),Background=Brush("CardGradient"),Padding=new Thickness(12)};
        var layout=new DockPanel();frame.Child=layout;
        var titleBar=new DockPanel{Margin=new Thickness(0,0,0,10)};DockPanel.SetDock(titleBar,Dock.Top);layout.Children.Add(titleBar);
        var close=new Button{Content=FeatherIcons.Make("x"),Width=34,Height=32,Padding=new Thickness(0),Margin=new Thickness(8,0,0,0),ToolTip="关闭"}; close.Click+=(_,_)=>Close();DockPanel.SetDock(close,Dock.Right);titleBar.Children.Add(close);
        if(resizable){var max=new Button{Content=FeatherIcons.Make("square"),Width=34,Height=32,Padding=new Thickness(0),Margin=new Thickness(8,0,0,0),ToolTip="最大化 / 还原"};max.Click+=(_,_)=>ToggleMax();StateChanged+=(_,_)=>max.Content=FeatherIcons.Make(WindowState==WindowState.Maximized?"copy":"square");DockPanel.SetDock(max,Dock.Right);titleBar.Children.Add(max);}
        var drag=new Border{Background=Brushes.Transparent,Padding=new Thickness(5,6,5,6),Child=new TextBlock{Text=title,FontSize=16,FontWeight=FontWeights.SemiBold,TextTrimming=TextTrimming.CharacterEllipsis}};
        drag.MouseLeftButtonDown+=(_,e)=>{if(e.ClickCount==2&&resizable){ToggleMax();return;}if(WindowState==WindowState.Normal)try{DragMove();}catch(InvalidOperationException){}};
        titleBar.Children.Add(drag);layout.Children.Add(body);Content=frame;AcrylicChrome.Attach(this,frame);
        PreviewKeyDown+=(_,e)=>{if(e.Key==Key.Escape){e.Handled=true;Close();}};
    }
    private void ToggleMax()=>WindowState=WindowState==WindowState.Maximized?WindowState.Normal:WindowState.Maximized;
    public void SetBody(UIElement content)=>body.Content=content;
    internal Brush Brush(string key)=>(Brush)FindResource(key);
    internal Button ActionButton(string text, bool primary=false)=>new(){Content=text,Style=(Style)FindResource(primary?"PrimaryButton":"PillButton")};
}
internal static class GlassMessage
{
    public static MessageBoxResult Show(Window owner,string message,string title="提示",MessageBoxButton buttons=MessageBoxButton.OK,MessageBoxImage image=MessageBoxImage.None)
    {
        // Only OK and OKCancel are used by this application. Closing never confirms a destructive action.
        var w=new GlassWindow(owner,title,590,390,false);
        var panel=new DockPanel{Margin=new Thickness(8)};
        var actions=new StackPanel{Orientation=Orientation.Horizontal,HorizontalAlignment=HorizontalAlignment.Right,Margin=new Thickness(0,12,0,0)};DockPanel.SetDock(actions,Dock.Bottom);panel.Children.Add(actions);
        bool confirm=buttons==MessageBoxButton.OKCancel;
        if(confirm){var cancel=w.ActionButton("取消");cancel.IsDefault=true;cancel.Click+=(_,_)=>w.DialogResult=false;actions.Children.Add(cancel);}
        var ok=w.ActionButton(confirm?"确认":"知道了",!confirm);ok.IsDefault=!confirm;ok.Click+=(_,_)=>w.DialogResult=true;actions.Children.Add(ok);
        var text=new TextBlock{Text=message,TextWrapping=TextWrapping.Wrap,LineHeight=23,Margin=new Thickness(3)};
        if(image==MessageBoxImage.Warning||image==MessageBoxImage.Error){var hint=new TextBlock{Text="请仔细核对以下信息",Foreground=w.Brush("WarnBrush"),FontWeight=FontWeights.SemiBold,Margin=new Thickness(3,0,3,8)};DockPanel.SetDock(hint,Dock.Top);panel.Children.Add(hint);}
        panel.Children.Add(new ScrollViewer{Content=text,VerticalScrollBarVisibility=ScrollBarVisibility.Auto});w.SetBody(panel);
        return w.ShowModal()==true?MessageBoxResult.OK:confirm?MessageBoxResult.Cancel:MessageBoxResult.OK;
    }
}
