using System.Net;
using System.Net.Http.Headers;

namespace TlsCheck;

public static class HttpProbe
{
    public static async Task<(bool redirectToHttps, bool httpsReachable, bool hsts, int? status)>
        CheckAsync(string host, int timeoutMs, CancellationToken ct)
    {
        var handler = new SocketHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromMilliseconds(timeouMs)
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };

        bool redirectsToHttps = false;
        bool httpsReachable = false;
        bool hsts = false;
        int? status = null;

        // 1) Check if http:// redirects to https://
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Head, $"http://{host}/");
            using var res = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if ((int)res.StatusCode is >= 300 and < 400)
            {
                if (res.Headers.Location is Uri loc && loc.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                    redirectsToHttps = true;
            }
        }
        catch { /* ignore for version 0.1 */ }

        // 2) HEAD https:// and look for HSTS
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Head, $"https://{host}/");
            using var res = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            status = (int)res.StatusCode;
            httpsReachable = res.IsSuccessStatusCode || (int)res.StatusCode is >= 200 and < 400;
            hsts = res.Headers.TryGetValues("Strict-Transport-Security", out var _);
        }
        catch
        {
            httpsReachable = false;
        }

        return (redirectsToHttps, httpsReachable, hsts, status);
    }
}