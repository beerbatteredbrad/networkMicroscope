namespace NetworkMicroscope.Core;

public interface INetworkIntelligenceProvider
{
    Task<IntelligenceResult> GetAsnInfoAsync(string ipAddress);
    Task<IntelligenceResult> GetGeoIpInfoAsync(string ipAddress);
}

public class IntelligenceResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public Dictionary<string, string> Data { get; set; } = new();
}