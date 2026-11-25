using System.Numerics;
using System.Security.Cryptography;
using System.Text;
namespace Guardian.Core;
// SimHash over normalized IL token 4-grams. Not TLSH, and not a malware verdict.
public static class IlSimilarity
{
    public static string Fingerprint(string normalized)
    {
        var tokens=normalized.Split(';',StringSplitOptions.RemoveEmptyEntries);var weights=new int[64];var seen=new HashSet<string>();
        int stride=Math.Max(1,tokens.Length/1024);
        for(int i=0;i+3<tokens.Length;i+=stride){string gram=string.Join(";",tokens,i,4);if(!seen.Add(gram))continue;ulong h=System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(SHA256.HashData(Encoding.UTF8.GetBytes(gram)));for(int j=0;j<64;j++)weights[j]+=((h>>j)&1)==1?1:-1;}
        ulong result=0;for(int j=0;j<64;j++)if(weights[j]>0)result|=1UL<<j;return result.ToString("X16");
    }
    public static int Distance(string a,string b)=>BitOperations.PopCount(Convert.ToUInt64(a,16)^Convert.ToUInt64(b,16));
    public static void Annotate(List<ScanRow> rows,CancellationToken ct)
    {
        // Bound candidate comparisons; 8 bands, skip common buckets and exact matches.
        var index=new Dictionary<(int,byte),List<(int Row,ulong Hash)>>();var matches=new HashSet<int>();int budget=2000000;
        string Identity(ScanRow r)=>r.WorkshopId.Length>0?r.WorkshopId:Path.GetDirectoryName(r.Path)??r.Mod;
        for(int i=0;i<rows.Count&&budget>0;i++)foreach(var f in (rows[i].Analysis.FuzzyFingerprints??[]).Take(256)){
            ct.ThrowIfCancellationRequested();if(!ulong.TryParse(f,System.Globalization.NumberStyles.HexNumber,null,out var hash))continue;
            for(int band=0;band<8;band++){var key=(band,(byte)(hash>>(band*8)));if(!index.TryGetValue(key,out var bucket))index[key]=bucket=[];
                foreach(var p in bucket){if(--budget<=0)break;if(p.Row==i||p.Hash==hash||Identity(rows[p.Row])==Identity(rows[i]))continue;if(BitOperations.PopCount(hash^p.Hash)<=7){matches.Add(i);matches.Add(p.Row);}}
                if(bucket.Count<64)bucket.Add((i,hash));if(budget<=0)break;}
            if(budget<=0)break;
        }
        foreach(var i in matches){var r=rows[i];rows[i]=r with {Similarity=r.Similarity=="—"?"近似 IL 结构":r.Similarity+" / 近似 IL",Analysis=r.Analysis with {Risk=r.Analysis.Risk==Risk.Clear?Risk.Review:r.Analysis.Risk,Evidence=r.Analysis.Evidence.Append(new Evidence("跨包近似 IL 结构",Risk.Review,"SimHash","归一化四元组近似匹配（距离 ≤ 7），可能为共用库；不是木马定论")).ToList()}};}
    }
}
