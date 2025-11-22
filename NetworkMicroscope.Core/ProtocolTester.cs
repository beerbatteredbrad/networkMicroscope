using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetworkMicroscope.Core;

public class ProtocolResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public Dictionary<string, string> Details { get; set; } = new();
}

public class ProtocolTester
{
    private readonly string _target;
    private readonly int _port;

    public ProtocolTester(string target, int port)
    {
        _target = target;
        _port = port;
    }

    public async Task<ProtocolResult> TestHttp3SupportAsync()
    {
        var result = new ProtocolResult();
        try
        {
            // HTTP/3 requires a specific setup. 
            // We try to connect to the target via HTTPS and request HTTP/3.
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator; // For testing

            using var client = new HttpClient(handler);
            client.DefaultRequestVersion = HttpVersion.Version30;
            client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact; // Force HTTP/3

            // Construct URL. If port is 443, standard https. Else specify port.
            string url = _port == 443 ? $"https://{_target}/" : $"https://{_target}:{_port}/";

            // Set a reasonable timeout
            client.Timeout = TimeSpan.FromSeconds(5);

            var response = await client.GetAsync(url);

            result.Success = true;
            result.Details["ProtocolVersion"] = response.Version.ToString();
            result.Details["StatusCode"] = response.StatusCode.ToString();
            
            if (response.Version == HttpVersion.Version30)
            {
                result.Message = "Target supports HTTP/3 (QUIC).";
            }
            else
            {
                result.Message = $"Target responded with {response.Version}, not HTTP/3.";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"HTTP/3 Test Failed: {ex.Message}";
        }
        return result;
    }

    public async Task<ProtocolResult> AnalyzeTlsAsync(IPAddress? specificIp = null)
    {
        var result = new ProtocolResult();
        try
        {
            using var client = new TcpClient();
            Task connectTask;
            int timeoutSeconds = 5;

            if (specificIp != null)
            {
                connectTask = client.ConnectAsync(specificIp, _port);
                timeoutSeconds = 2;
            }
            else
            {
                connectTask = client.ConnectAsync(_target, _port);
            }

            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(timeoutSeconds));
            var completedTask = await Task.WhenAny(connectTask, timeoutTask);

            if (completedTask == timeoutTask)
            {
                result.Success = false;
                result.Message = $"Connection timed out after {timeoutSeconds} seconds.";
                return result;
            }
            await connectTask; // Propagate exceptions

            using var sslStream = new SslStream(
                client.GetStream(),
                false,
                new RemoteCertificateValidationCallback(ValidateServerCertificate),
                null
            );

            // Authenticate - Always use _target (hostname) for SNI
            await sslStream.AuthenticateAsClientAsync(_target);

            result.Success = true;
            result.Message = "TLS Handshake Successful.";
            
            result.Details["Protocol"] = sslStream.SslProtocol.ToString();
            result.Details["CipherSuite"] = sslStream.NegotiatedCipherSuite.ToString();
            result.Details["IsAuthenticated"] = sslStream.IsAuthenticated.ToString();
            result.Details["IsEncrypted"] = sslStream.IsEncrypted.ToString();
            result.Details["IsSigned"] = sslStream.IsSigned.ToString();

            if (sslStream.RemoteCertificate != null)
            {
                var cert = new X509Certificate2(sslStream.RemoteCertificate);
                result.Details["CertIssuer"] = cert.Issuer;
                result.Details["CertSubject"] = cert.Subject;
                result.Details["CertThumbprint"] = cert.Thumbprint;
                result.Details["CertExpiration"] = cert.NotAfter.ToString("O");
                result.Details["CertEffective"] = cert.NotBefore.ToString("O");
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"TLS Analysis Failed: {ex.Message}";
        }
        return result;
    }

    private static bool ValidateServerCertificate(
          object sender,
          X509Certificate? certificate,
          X509Chain? chain,
          SslPolicyErrors sslPolicyErrors)
    {
        // We want to analyze the cert even if it has errors, so we return true here 
        // but we could log the errors if we wanted to be strict.
        // For a diagnostic tool, we usually want to see the connection succeed to inspect it.
        return true;
    }
}