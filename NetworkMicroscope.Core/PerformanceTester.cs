using System.Diagnostics;
using System.Net.NetworkInformation;

namespace NetworkMicroscope.Core;

public class PerformanceResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public double Value { get; set; } // Latency in ms, or Bandwidth in Mbps
    public string Unit { get; set; } = string.Empty;
}

public class PerformanceTester
{
    private readonly string _target;

    public PerformanceTester(string target)
    {
        _target = target;
    }

    public async Task<PerformanceResult> TestLatencyAsync()
    {
        var result = new PerformanceResult { Unit = "ms" };
        try
        {
            using var ping = new Ping();
            // Ping options can be added here
            var reply = await ping.SendPingAsync(_target, 4000);

            if (reply.Status == IPStatus.Success)
            {
                result.Success = true;
                result.Value = reply.RoundtripTime;
                result.Message = $"Ping to {_target} successful.";
            }
            else
            {
                result.Success = false;
                result.Message = $"Ping failed: {reply.Status}";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"Ping exception: {ex.Message}";
        }
        return result;
    }

    public async Task<PerformanceResult> TestBandwidthAsync(string downloadUrl)
    {
        var result = new PerformanceResult { Unit = "Mbps" };
        
        if (string.IsNullOrWhiteSpace(downloadUrl))
        {
            result.Success = false;
            result.Message = "No download URL provided for bandwidth test.";
            return result;
        }

        try
        {
            using var client = new HttpClient();
            // Don't buffer the whole response, we just want to read the stream
            using var response = await client.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            using var stream = await response.Content.ReadAsStreamAsync();
            var buffer = new byte[8192];
            long totalBytesRead = 0;
            var stopwatch = Stopwatch.StartNew();
            
            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                totalBytesRead += bytesRead;
            }
            
            stopwatch.Stop();
            
            double seconds = stopwatch.Elapsed.TotalSeconds;
            if (seconds == 0) seconds = 0.001; // Avoid divide by zero

            double bits = totalBytesRead * 8;
            double megabits = bits / 1_000_000;
            double mbps = megabits / seconds;

            result.Success = true;
            result.Value = Math.Round(mbps, 2);
            result.Message = $"Downloaded {totalBytesRead} bytes in {seconds:F2}s.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"Bandwidth test failed: {ex.Message}";
        }

        return result;
    }
}