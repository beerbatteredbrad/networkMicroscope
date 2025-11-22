using System.Net.Http.Json;
using System.Text.Json;

namespace NetworkMicroscope.Core;

public class IpInfoProvider : INetworkIntelligenceProvider
{
    private readonly HttpClient _httpClient;

    public IpInfoProvider(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<IntelligenceResult> GetAsnInfoAsync(string ipAddress)
    {
        // Using ipinfo.io free tier (no token required for basic info, but rate limited)
        // Format: https://ipinfo.io/{ip}/json
        return await FetchIpInfoAsync(ipAddress);
    }

    public async Task<IntelligenceResult> GetGeoIpInfoAsync(string ipAddress)
    {
        // ipinfo.io returns both ASN and Geo in the same response usually
        return await FetchIpInfoAsync(ipAddress);
    }

    private async Task<IntelligenceResult> FetchIpInfoAsync(string ipAddress)
    {
        var result = new IntelligenceResult();
        try
        {
            // If target is a domain, we should resolve it first, but for now assuming IP or letting API handle it if it supports it.
            // ipinfo.io supports IPs.
            
            var response = await _httpClient.GetAsync($"https://ipinfo.io/{ipAddress}/json");
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var data = JsonSerializer.Deserialize<Dictionary<string, object>>(json);

                result.Success = true;
                result.Message = "Successfully retrieved intelligence data.";
                
                if (data != null)
                {
                    foreach (var kvp in data)
                    {
                        result.Data[kvp.Key] = kvp.Value.ToString() ?? "";
                    }
                }
            }
            else
            {
                result.Success = false;
                result.Message = $"API request failed with status: {response.StatusCode}";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"Intelligence lookup failed: {ex.Message}";
        }
        return result;
    }
}