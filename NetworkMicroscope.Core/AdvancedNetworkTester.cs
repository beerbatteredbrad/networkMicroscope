using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;

namespace NetworkMicroscope.Core;

public class AdvancedNetworkTester
{
    private readonly string _target;

    public AdvancedNetworkTester(string target)
    {
        _target = target;
    }

    public async Task<List<string>> RunTracerouteAsync(int maxHops = 30)
    {
        var results = new List<string>();
        using var ping = new Ping();
        var options = new PingOptions(1, true); // Start with TTL 1, DontFragment=true
        var buffer = new byte[32];
        new Random().NextBytes(buffer);

        IPAddress? targetIp = null;
        try
        {
            var entries = await Dns.GetHostAddressesAsync(_target);
            targetIp = entries.FirstOrDefault();
        }
        catch
        {
            results.Add($"Could not resolve {_target}");
            return results;
        }

        if (targetIp == null)
        {
            results.Add($"No IP found for {_target}");
            return results;
        }

        results.Add($"Tracing route to {_target} [{targetIp}] over a maximum of {maxHops} hops:");

        var stopwatch = new Stopwatch();
        int consecutiveTimeouts = 0;
        const int maxConsecutiveTimeouts = 5;

        for (int ttl = 1; ttl <= maxHops; ttl++)
        {
            options.Ttl = ttl;
            stopwatch.Restart();
            
            try
            {
                // Reduced timeout to 2 seconds to prevent hanging on blocked paths
                var reply = await ping.SendPingAsync(targetIp, 2000, buffer, options);
                stopwatch.Stop();

                string hopInfo = $"{ttl}\t{stopwatch.ElapsedMilliseconds}ms\t{reply.Address}";

                if (reply.Status == IPStatus.Success)
                {
                    results.Add($"{hopInfo} (Reached Target)");
                    break;
                }
                else if (reply.Status == IPStatus.TtlExpired)
                {
                    results.Add(hopInfo);
                    consecutiveTimeouts = 0; // Reset counter on success
                }
                else if (reply.Status == IPStatus.TimedOut)
                {
                    results.Add($"{ttl}\t*\tRequest timed out.");
                    consecutiveTimeouts++;
                    
                    if (consecutiveTimeouts >= maxConsecutiveTimeouts)
                    {
                        results.Add("Stopping traceroute after multiple consecutive timeouts (likely blocked).");
                        break;
                    }
                }
                else
                {
                    results.Add($"{ttl}\t{stopwatch.ElapsedMilliseconds}ms\t{reply.Status}");
                    consecutiveTimeouts = 0;
                }
            }
            catch (Exception ex)
            {
                results.Add($"{ttl}\tError: {ex.Message}");
            }
        }

        return results;
    }

    public async Task<string> DiscoverPathMtuAsync()
    {
        // Basic PMTU Discovery using Ping with DontFragment
        // We start high and go low, or binary search.
        // Ethernet MTU is usually 1500. IP Header (20) + ICMP Header (8) = 28 bytes overhead.
        // Max payload = 1472.

        IPAddress? targetIp;
        try
        {
            var entries = await Dns.GetHostAddressesAsync(_target);
            targetIp = entries.FirstOrDefault();
        }
        catch
        {
            return "Could not resolve target for PMTU discovery.";
        }

        if (targetIp == null) return "No IP found.";

        using var ping = new Ping();
        var options = new PingOptions(64, true); // TTL 64, DontFragment = TRUE

        int low = 68; // Minimum IPv4 MTU
        int high = 1472; // Standard Ethernet Payload
        int lastSuccess = 0;

        // Binary search for the max payload size
        while (low <= high)
        {
            int mid = (low + high) / 2;
            byte[] buffer = new byte[mid];
            
            try
            {
                var reply = await ping.SendPingAsync(targetIp, 2000, buffer, options);
                
                if (reply.Status == IPStatus.Success)
                {
                    lastSuccess = mid;
                    low = mid + 1;
                }
                else if (reply.Status == IPStatus.PacketTooBig)
                {
                    high = mid - 1;
                }
                else
                {
                    // Other errors (timeout), assume lost or blocked, treat as too big or retry?
                    // For simplicity, treat as upper bound failure
                    high = mid - 1;
                }
            }
            catch
            {
                high = mid - 1;
            }
        }

        if (lastSuccess > 0)
        {
            // MTU = Payload + IP Header (20) + ICMP Header (8)
            int estimatedMtu = lastSuccess + 28; 
            return $"Estimated Path MTU: {estimatedMtu} bytes (Payload: {lastSuccess} bytes)";
        }
        else
        {
            return "Could not determine Path MTU (ICMP might be blocked).";
        }
    }

    public async Task<List<string>> ScanPortsAsync(IEnumerable<int> ports)
    {
        var results = new List<string>();
        var portList = ports.ToList();
        var tasks = portList.Select(async port =>
        {
            using var client = new TcpClient();
            try
            {
                var connectTask = client.ConnectAsync(_target, port);
                var timeoutTask = Task.Delay(1000); // 1 second timeout per port
                
                var completed = await Task.WhenAny(connectTask, timeoutTask);
                if (completed == connectTask)
                {
                    // Ensure the task completed successfully (didn't fault)
                    await connectTask; 
                    if (client.Connected)
                    {
                        return $"Port {port}: OPEN";
                    }
                }
            }
            catch
            {
                // Ignore errors (Closed/Filtered)
            }
            return null;
        });

        var scanResults = await Task.WhenAll(tasks);
        var openPorts = scanResults.Where(r => r != null).ToList();
        results.AddRange(openPorts!);
        
        if (results.Count == 0) 
        {
            results.Add("No open ports found in the specified range.");
        }
        else if (results.Count == portList.Count)
        {
            results.Add("[WARNING] All scanned ports are OPEN. This usually indicates a firewall or load balancer is intercepting connections (e.g., Azure Front Door).");
        }
        
        return results;
    }
}