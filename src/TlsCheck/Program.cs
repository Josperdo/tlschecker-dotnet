using System.Text.Json;
using TlsCheck;

var opts = ParseArgs(args);
if (!Util.ReadTargets(opts).Any())
{
    Util.PrintUsage();
    return 1;
}

var outPath = opts.OutFile;
CancellationTokenSource? globalCts = new();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; globalCts.Cancel(); };

var results = new List<TlsResult>();
int expiringFlagged = 0;

foreach (var target in Util.ReadTargets(opts))
{
    if (globalCts.IsCancellationRequested) break;

    var host = Util.NormalizeHost(target);

    var (redir, httpsOk, hsts, status) =
        await HttpProbe.CheckAsync(host, opts.TimeoutMs, globalCts.Token);

    var (proto, cert, tlsErr) =
        await TlsProbe.HandshakeAsync(host, opts.TimeoutMs, globalCts.Token);

    DateTimeOffset? notAfter = cert?.NotAfter.ToUniversalTime();
    var days = Util.DaysUntil(notAfter);

    var res = new TlsResult(
        TsUtc: DateTimeOffset.UtcNow,
        Target: target,
        Host: host,
        HttpRedirectsToHttps: redir,
        HttpsReachable: httpsOk,
        HttpStatus: status,
        HstsPresent: hsts,
        TlsProtocol: proto,
        CertIssuer: cert?.Issuer,
        CertNotAfterUtc: notAfter,
        CertDaysRemaining: days,
        Error: tlsErr
    );

    results.Add(res);

    // Emit as JSONL (stdout or file)
    if (string.IsNullOrWhiteSpace(outPath))
        Console.WriteLine(JsonSerializer.Serialize(res));
    else
        await Util.AppendJsonLineAsync(outPath, res, globalCts.Token);

    if (opts.FailIfExpiringDays is int thr && days is int d && d <= thr) expiringFlagged++;
}

if (opts.FailIfExpiringDays is not null && expiringFlagged > 0)
    return 2;

return 0;

// -----------------
static Options ParseArgs(string[] args)
{
    var o = new Options();
    for (int i = 0; i < args.Length; i++)
    {
        var a = args[i];
        if (a == "--in" && i + 1 < args.Length) { o.InputFile = args[++i]; continue; }
        if (a == "--out" && i + 1 < args.Length) { o.OutFile = args[++i]; continue; }
        if (a == "--timeout-ms" && i + 1 < args.Length && int.TryParse(args[++i], out var t)) { o.TimeoutMs = t; continue; }
        if (a == "--fail-if-expiring" && i + 1 < args.Length && int.TryParse(args[++i], out var f)) { o.FailIfExpiringDays = f; continue; }
        if (a.StartsWith("--")) continue;
        o.Targets.Add(a);
    }
    return o;
}