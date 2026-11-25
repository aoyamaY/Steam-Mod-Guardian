namespace Guardian.Core;
public static class LaunchChecks
{
    public static bool SameFiles(ScanReport before,ScanReport after)
    {
        if(!before.Roots.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(after.Roots)||before.Files.Count!=after.Files.Count)return false;
        var map=before.Files.ToDictionary(x=>x.Path,StringComparer.OrdinalIgnoreCase);
        return after.Files.All(r=>map.TryGetValue(r.Path,out var prev)&&r.Sha256.Length==64&&r.Sha256.Equals(prev.Sha256,StringComparison.OrdinalIgnoreCase)&&r.Analysis.Risk==prev.Analysis.Risk&&r.DownloadLabel==prev.DownloadLabel&&r.YaraLabel==prev.YaraLabel&&r.AmsiLabel==prev.AmsiLabel);
    }
}
