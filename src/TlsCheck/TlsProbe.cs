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

        }
        catch
        {
            httpsReachable = false;
        }
        
    }
}