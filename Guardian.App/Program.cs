using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace Guardian.App;

internal static class StartupLog
{
    private static readonly object Gate = new();
    public static string LogPath { get; private set; } = "(日志文件不可写)";

    public static void Write(string message)
    {
        lock (Gate)
        {
            try
            {
                string dir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DuckovModGuardian");
                Append(dir,message);
            }
            catch
            {
                try { Append(Path.Combine(Path.GetTempPath(),"DuckovModGuardian"),message); }
                catch { }
            }
        }
    }
    private static void Append(string dir,string message)
    {
        Directory.CreateDirectory(dir);
        var path=Path.Combine(dir,"startup.log");
        if(File.Exists(path) && new FileInfo(path).Length>2*1024*1024)
            File.Move(path,path+".old",true);
        File.AppendAllText(path,$"[{DateTimeOffset.Now:O}] {message}{Environment.NewLine}");
        LogPath=path;
    }
}

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        bool smokeTest = Array.Exists(args, a => a == "--smoke-test-ui");
        if(Array.Exists(args,a=>a=="--smoke-test-runtime"))
        {try{var sample=TcpSnapshot.Remote(Environment.ProcessId);StartupLog.Write("PASS runtime TCP table smoke test");return 0;}catch(Exception ex){StartupLog.Write("Runtime smoke test failed: "+ex);return 1;}}
        StartupLog.Write($"=== Steam Mod Guardian 2.1.0 start; PID {Environment.ProcessId}; {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription} ===");
        AppDomain.CurrentDomain.UnhandledException += (_,e) => StartupLog.Write("Unhandled exception: "+e.ExceptionObject);
        try
        {
            var app=new App();
            app.DispatcherUnhandledException += (_,e) =>
            {
                e.Handled=true;
                ReportFatal(e.Exception, smokeTest);
                app.Shutdown(1);
            };
            // App.xaml is empty; no generated InitializeComponent is required.
            // MainWindow initializes its own XAML in its constructor.
            app.ShutdownMode = ShutdownMode.OnLastWindowClose;
            StartupLog.Write("Application initialized");
            var window=new MainWindow(smokeTest);
            if (smokeTest)
            {
                window.ContentRendered += async (_,_) =>
                {
                    try { await window.RunUiChecksAsync(); StartupLog.Write("PASS UI smoke test: window, filters, scrollbars and custom dialog"); app.Shutdown(0); }
                    catch(Exception ex){ReportFatal(ex,true);app.Shutdown(1);}
                };
            }
            StartupLog.Write("Starting WPF message loop");
            int exit=app.Run(window);
            StartupLog.Write("Application exited: "+exit);
            return exit;
        }
        catch(Exception ex)
        {
            ReportFatal(ex, smokeTest);
            return 1;
        }
    }
    private static void ReportFatal(Exception ex, bool smokeTest)
    {
        StartupLog.Write("Fatal: "+ex);
        if (smokeTest) return;
        try { MessageBox.Show("程序启动或运行失败：\n"+ex.Message+"\n\n详细日志：\n"+StartupLog.LogPath,"Steam Mod Guardian",MessageBoxButton.OK,MessageBoxImage.Error); }
        catch { }
    }
}
