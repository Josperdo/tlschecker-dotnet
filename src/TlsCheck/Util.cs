using System.Text.Json;

namespace TlsCheck;

public static class Util
{
    public static IEnumerable<string> ReadTargets(Options o)
    {
        if (o.InputFile is not null && File.Exists(o.InputFile))
        {
            foreach (var line in File.ReadAllLines(o.InputFile))
            {
                var t = line.Trim();
                if (!string.IsNullOrEmpty(t)) yield return t;
            }
        }
        foreach (var t in o.Targets) yield return t;
    }

    public static string NormalizeHost(string target)
    {
        // Accept raw host or URL; return hostname
        if (Uri.TryCreate(target, UriKind.Absolute, out var u))
            return u.Host;
        if (Uri.TryCreate("https://" + target, UriKind.Absolute, out var u2))
            return u2.Host;
        return target;
    }

    public static int? DaysUntil(DateTimeOffset? when)
    {
        if (when is null) return null;
        var days = (int)Math.Floor((when.Value - DateTimeOffset.UtcNow).TotalDays);
        return days;
    }

    public static async Task AppendJsonLineAsync(string path, object obj, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = false });
        await File.AppendAllTextAsync(path, json + Environment.NewLine, ct);
    }

    public static void PrintUsage()
    {
        Console.WriteLine(
@"tlscheck v0.1
Usage:
  tlscheck [--in targets.txt] [--out out.jsonl] [--timeout-ms 7000] [--fail-if-expiring 30] [targets...]

Examples:
  tlscheck --in targets.txt --out examples/sample.jsonl --fail-if-expiring 30
  tlscheck example.com neverssl.com");
    }
}