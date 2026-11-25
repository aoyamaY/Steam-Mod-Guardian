using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shell;
namespace Guardian.App;

// Keep a normal composited HWND (not AllowsTransparency/layered) for official DWM acrylic.
internal static class AcrylicChrome
{
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd,int attribute,ref int value,int size);
    [StructLayout(LayoutKind.Sequential)] struct Rect {public int Left,Top,Right,Bottom;}
    [DllImport("user32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetWindowRect(IntPtr hwnd,out Rect rect);
    [DllImport("gdi32.dll")] static extern IntPtr CreateRoundRectRgn(int l,int t,int r,int b,int w,int h);
    [DllImport("user32.dll")] static extern int SetWindowRgn(IntPtr hwnd,IntPtr region,bool redraw);
    [DllImport("gdi32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool DeleteObject(IntPtr obj);
    static int Attr(IntPtr hwnd,int attr,int value)=>DwmSetWindowAttribute(hwnd,attr,ref value,4);
    internal static void Attach(Window window, System.Windows.Controls.Border surface, Action<string>? status=null)
    {
        bool fallback=false; IntPtr handle=IntPtr.Zero;
        var solid=new SolidColorBrush(Color.FromRgb(24,28,35));
        var tint=new SolidColorBrush(Color.FromArgb(72,14,19,27));
        void RoundFallback()
        {
            if(!fallback||handle==IntPtr.Zero)return;
            if(window.WindowState!=WindowState.Normal){SetWindowRgn(handle,IntPtr.Zero,true);return;}
            if(!GetWindowRect(handle,out var r))return;
            int radius=Math.Max(18,(int)Math.Round(44*VisualTreeHelper.GetDpi(window).DpiScaleX));
            var region=CreateRoundRectRgn(0,0,r.Right-r.Left+1,r.Bottom-r.Top+1,radius,radius);
            if(region!=IntPtr.Zero&&SetWindowRgn(handle,region,true)==0)DeleteObject(region);
        }
        void Apply()
        {
            if(handle==IntPtr.Zero)return;
            var chrome=WindowChrome.GetWindowChrome(window);
            bool supported=false;bool rounded=false;
            try
            {
                if(OperatingSystem.IsWindowsVersionAtLeast(10,0,22000)){Attr(handle,20,1);rounded=Attr(handle,33,2)==0;}
                // DWMWA_BORDER_COLOR=34; DWMWA_COLOR_NONE suppresses only the OS outer frame.
                if(OperatingSystem.IsWindowsVersionAtLeast(10,0,22000))Attr(handle,34,unchecked((int)0xFFFFFFFEu));
                if(OperatingSystem.IsWindowsVersionAtLeast(10,0,22621)&&!SystemParameters.HighContrast)
                {
                    if(chrome!=null)chrome.GlassFrameThickness=new Thickness(-1);
                    supported=Attr(handle,38,3)==0; // DWMSBT_TRANSIENTWINDOW: Desktop Acrylic
                }
                if(!supported){if(OperatingSystem.IsWindowsVersionAtLeast(10,0,22621))Attr(handle,38,1);if(chrome!=null)chrome.GlassFrameThickness=new Thickness(0);}
            }catch(Exception ex){StartupLog.Write("Acrylic unavailable: "+ex.Message);supported=false;if(chrome!=null)chrome.GlassFrameThickness=new Thickness(0);}
            fallback=!rounded;
            window.Background=supported?Brushes.Transparent:solid;
            if(HwndSource.FromHwnd(handle)?.CompositionTarget is HwndTarget target)target.BackgroundColor=supported?Colors.Transparent:solid.Color;
            surface.Background=supported?tint:solid;
            surface.BorderThickness=new Thickness(0);
            surface.CornerRadius=window.WindowState==WindowState.Maximized?new CornerRadius(0):new CornerRadius(22);
            if(fallback)RoundFallback();
                        StartupLog.Write($"Chrome: acrylic request={supported}; DWM round request={rounded}");
        }
        window.SourceInitialized+=(_,_)=>{handle=new WindowInteropHelper(window).Handle;Apply();};
        window.Loaded+=(_,_)=>Apply();
        window.SizeChanged+=(_,_)=>RoundFallback();
        window.StateChanged+=(_,_)=>{surface.CornerRadius=window.WindowState==WindowState.Maximized?new CornerRadius(0):new CornerRadius(22);RoundFallback();};
        // High contrast may be changed while the app is running.
        System.ComponentModel.PropertyChangedEventHandler changed=(_,e)=>{if(e.PropertyName==nameof(SystemParameters.HighContrast))window.Dispatcher.InvokeAsync(Apply);};
        SystemParameters.StaticPropertyChanged+=changed;
        window.Closed+=(_,_)=>{SystemParameters.StaticPropertyChanged-=changed;handle=IntPtr.Zero;};
    }
}
