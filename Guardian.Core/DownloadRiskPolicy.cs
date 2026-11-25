namespace Guardian.Core;
public static class DownloadRiskPolicy
{
    public static bool IsFileDownload(string label)=>label is "直接文件下载 API" or "疑似下载落盘";
    public static Analysis Apply(Analysis a)
    {
        if(!IsFileDownload(a.Download))return a;
        const string rule="文件下载最高风险策略";
        var evidence=a.Evidence.Any(e=>e.Rule==rule)?a.Evidence:a.Evidence.Prepend(new Evidence(rule,Risk.Critical,"静态分析",a.Download+"；按用户设定升至极高风险。仅代表下载能力或疑似行为，未证明实际下载或恶意。" )).ToList();
        return a with {Risk=Risk.Critical,Evidence=evidence};
    }
}
