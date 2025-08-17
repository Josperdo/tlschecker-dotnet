using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace TlsCheck;

public static class TlsProbe
{
    public static async Task<(string? protocol, X509Certificate2? cert, string? error)>
        HandshakeAsync(string host, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);

            await tcp.ConnectAsync(host, 443, cts.Token);
            await using var stream = tcp.GetStream();
            using var ssl = new SslStream(stream, false, (_, _, _, _) => true); // we only observe

            var options = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                // Let OS pick best; include TLS1.3 when available
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            };

            await ssl.AuthenticateAsClientAsync(options, cts.Token);

            var proto = ssl.SslProtocol.ToString();
            var remote = ssl.RemoteCertificate;
            X509Certificate2? cert2 = null;
            if (remote is not null)
                cert2 = new X509Certificate2(remote);

            return (proto, cert2, null);
        }
        catch (Exception ex)
        {
            return (null, null, ex.GetType().Name + ": " + ex.Message);
        }
    }
}