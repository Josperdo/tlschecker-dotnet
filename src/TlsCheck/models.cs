using System.Text.Json.Serizalization;

namespace TlsCheck;

public record TlsRecord (
    DateTimeOffset TsUtc,
    string Target,                 // what the user provided
    string Host,                   // normalized host
    bool HttpRedirectsToHttps,     // http:// → 301/302 → https://
    bool HttpsReachable,           // HEAD https succeeded
    int? HttpStatus,               // last status (https)
    bool HstsPresent,              // Strict-Transport-Security present
    string? TlsProtocol,           // e.g., Tls12, Tls13
    string? CertIssuer,
    DateTimeOffset? CertNotAfterUtc,
    int? CertDaysRemaining,
    string? Error                  // non-fatal probe error summary
);

public sealed class Options
{
    public List<string> Targets { get; } = new();
    public string? InputFile { get; set; } = null;
    public string? OutFile { get; set; } = null;
    public int TimeoutMs { get; set; } = 7000;
    public int? FailIfExpiringDays {get; set; } = null;
}