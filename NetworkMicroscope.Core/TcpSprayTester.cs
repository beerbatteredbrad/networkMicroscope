using System.Diagnostics;
using System.Net.Sockets;

namespace NetworkMicroscope.Core;

public class TcpSprayResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public int Sent { get; set; }
    public int Received { get; set; }
    public double LossPercentage { get; set; }
    public double MinLatency { get; set; }
    public double MaxLatency { get; set; }
    public double AvgLatency { get; set; }
    public double Jitter { get; set; }
}

public class TcpSprayTester
{
    private readonly string _target;
    private readonly int _port;

    public TcpSprayTester(string target, int port)
    {
        _target = target;
        _port = port;
    }

    public async Task<TcpSprayResult> RunSprayAsync(int count = 20, int delayMs = 100, IProgress<(int completed, int total)>? progress = null)
    {
        var result = new TcpSprayResult { Sent = count };
        var latencies = new List<double>();
        var stopwatch = new Stopwatch();

        for (int i = 0; i < count; i++)
        {
            try
            {
                using var client = new TcpClient();
                stopwatch.Restart();
                
                var connectTask = client.ConnectAsync(_target, _port);
                var timeoutTask = Task.Delay(2000); // 2s timeout per probe

                var completed = await Task.WhenAny(connectTask, timeoutTask);
                stopwatch.Stop();

                if (completed == connectTask)
                {
                    await connectTask; // Propagate exceptions
                    if (client.Connected)
                    {
                        latencies.Add(stopwatch.Elapsed.TotalMilliseconds);
                        result.Received++;
                    }
                }
            }
            catch
            {
                // Connection failed (Loss)
            }

            progress?.Report((i + 1, count));

            if (i < count - 1) await Task.Delay(delayMs);
        }

        result.LossPercentage = ((double)(result.Sent - result.Received) / result.Sent) * 100;
        
        if (latencies.Count > 0)
        {
            result.MinLatency = Math.Round(latencies.Min(), 2);
            result.MaxLatency = Math.Round(latencies.Max(), 2);
            result.AvgLatency = Math.Round(latencies.Average(), 2);
            
            // Calculate Jitter (Standard Deviation of Latency)
            double sumSquares = latencies.Sum(l => Math.Pow(l - result.AvgLatency, 2));
            result.Jitter = Math.Round(Math.Sqrt(sumSquares / latencies.Count), 2);
            
            result.Success = true;
            result.Message = $"TCP Spray Complete. Loss: {result.LossPercentage:F1}%";
        }
        else
        {
            result.Success = false;
            result.Message = "TCP Spray Failed: 100% Packet Loss.";
        }

        return result;
    }
}
