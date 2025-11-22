namespace NetworkMicroscope.Core;

public class NetworkIntelligenceTester
{
    private readonly string _target;
    private readonly INetworkIntelligenceProvider _provider;

    public NetworkIntelligenceTester(string target, INetworkIntelligenceProvider provider)
    {
        _target = target;
        _provider = provider;
    }

    public async Task<IntelligenceResult> RunAsnLookupAsync()
    {
        // If target is a domain, we might need to resolve it to an IP first.
        // For simplicity, we'll assume the provider or caller handles resolution or the API supports it.
        // But typically ASN lookup is by IP.
        
        // Simple DNS resolution check
        string ipToQuery = _target;
        if (!System.Net.IPAddress.TryParse(_target, out _))
        {
            try
            {
                var entries = await System.Net.Dns.GetHostAddressesAsync(_target);
                if (entries.Length > 0)
                {
                    ipToQuery = entries[0].ToString();
                }
            }
            catch
            {
                // Keep original if resolution fails, maybe provider can handle it or it will fail there
            }
        }

        return await _provider.GetAsnInfoAsync(ipToQuery);
    }
}