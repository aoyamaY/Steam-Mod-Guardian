namespace Guardian.Core;
public enum Risk { Clear, Review, High, Critical, Unknown }
public sealed record Evidence(string Rule, Risk Risk, string Method, string Detail);
public sealed record Analysis(Risk Risk, string Kind, List<Evidence> Evidence, string? Error = null, List<string>? Fingerprints = null, string Download = "未发现", string YaraStatus = "未启用", List<string>? Hosts = null, string AmsiStatus = "未启用", List<string>? FuzzyFingerprints = null);
public sealed record ScanRow(string Mod, string WorkshopId, string Path, string Sha256, long Size, Analysis Analysis, bool Cached)
{
    public string AppId { get; init; } = "";
    public string GameName { get; init; } = "未关联游戏";
    public string NameSource { get; init; } = "目录/ID";
    public string Change { get; init; } = "基线";
    public string DownloadLabel => Analysis.Download == "未发现" && Analysis.Risk == Risk.Unknown ? "未知（未完成）" : Analysis.Download;
    public string Similarity { get; init; } = "—";
    public string HostLabel => string.Join(", ", (Analysis.Hosts??[]).Take(4));
    public string FileName => System.IO.Path.GetFileName(Path);
    public string YaraLabel => Analysis.YaraStatus;
    public string AmsiLabel => Analysis.AmsiStatus;
    public string RiskLabel => Analysis.Risk switch { Risk.Clear => "未发现风险", Risk.Review => "需复核", Risk.High => "高风险", Risk.Critical => "极高风险", _ => "未完成/未知" };
    public string Summary => Analysis.Error ?? (Analysis.Evidence.Count == 0 ? "未命中规则" : string.Join("；", Analysis.Evidence.Select(x => x.Rule).Distinct().Take(5)));
}
public sealed record ScanReport(DateTimeOffset Time, string RuleVersion, List<string> Roots, List<ScanRow> Files, List<string> Warnings);
public sealed record ScanProgress(int Done, int Total, string File);
