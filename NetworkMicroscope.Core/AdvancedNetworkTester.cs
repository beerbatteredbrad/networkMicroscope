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

    public static readonly int[] Top100Ports = new[] 
    { 
        7, 9, 13, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155
    };

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

        // Pre-flight check: Ensure target responds to ICMP at all
        try
        {
            var preCheck = await ping.SendPingAsync(targetIp, 2000, new byte[32], options);
            if (preCheck.Status != IPStatus.Success)
            {
                return $"Target does not respond to ICMP (Status: {preCheck.Status}). PMTU Discovery skipped.";
            }
        }
        catch
        {
            return "Target unreachable via ICMP. PMTU Discovery skipped.";
        }

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
                var reply = await ping.SendPingAsync(targetIp, 1000, buffer, options); // Reduced timeout to 1s for search
                
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

        // Resolve IP once to avoid 100 concurrent DNS lookups
        IPAddress? targetIp = null;
        if (IPAddress.TryParse(_target, out var ip))
        {
            targetIp = ip;
        }
        else
        {
            try
            {
                var ips = await Dns.GetHostAddressesAsync(_target);
                targetIp = ips.FirstOrDefault();
            }
            catch { /* Ignore DNS failure here, individual connects will fail */ }
        }

        // Use SemaphoreSlim to throttle concurrency (max 25 concurrent connections)
        using var semaphore = new SemaphoreSlim(25);

        var tasks = portList.Select(async port =>
        {
            await semaphore.WaitAsync();
            try
            {
                using var client = new TcpClient();
                var connectTask = targetIp != null 
                    ? client.ConnectAsync(targetIp, port) 
                    : client.ConnectAsync(_target, port); // Fallback if DNS pre-resolve failed

                var timeoutTask = Task.Delay(1500); // Increased timeout to 1.5s
                
                var completed = await Task.WhenAny(connectTask, timeoutTask);
                if (completed == connectTask)
                {
                    try 
                    {
                        await connectTask; // Propagate exceptions
                        if (client.Connected)
                        {
                            return $"Port {port}: OPEN";
                        }
                    }
                    catch { /* Connection failed */ }
                }
            }
            catch
            {
                // Ignore errors (Closed/Filtered)
            }
            finally
            {
                semaphore.Release();
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