using System.Net;
using System.Net.Security;
using NetworkMicroscope.Core;

namespace NetworkMicroscope.CLI;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Network Microscope CLI");
        
        // Basic argument parsing placeholder
        string target = "google.com";
        int port = 443;
        string testType = "all";
        string downloadUrl = "";
        int probes = 100;
        string alpn = "";

        // Simple manual parsing for now (can use System.CommandLine later)
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--target" && i + 1 < args.Length) target = args[i + 1];
            if (args[i] == "--port" && i + 1 < args.Length) int.TryParse(args[i + 1], out port);
            if (args[i] == "--test" && i + 1 < args.Length) testType = args[i + 1];
            if (args[i] == "--download-url" && i + 1 < args.Length) downloadUrl = args[i + 1];
            if (args[i] == "--probes" && i + 1 < args.Length) int.TryParse(args[i + 1], out probes);
            if (args[i] == "--alpn" && i + 1 < args.Length) alpn = args[i + 1];
        }

        Console.WriteLine($"Target: {target}, Port: {port}, Test: {testType}");
        Console.WriteLine("--------------------------------------------------");

        if (testType == "connectivity" || testType == "all")
        {
            RunConnectivityTests(target, port).Wait();
        }

        if (testType == "protocol" || testType == "all")
        {
            RunProtocolTests(target, port).Wait();
        }

        if (testType == "intelligence" || testType == "all")
        {
            RunIntelligenceTests(target).Wait();
        }

        if (testType == "performance" || testType == "all")
        {
            RunPerformanceTests(target, downloadUrl).Wait();
        }

        if (testType == "advanced" || testType == "all")
        {
            RunAdvancedTests(target).Wait();
        }

        if (testType == "ja4" || testType == "all")
        {
            RunJa4Tests(target, port, alpn).Wait();
        }

        if (testType == "tcpspray" || testType == "all")
        {
            RunTcpSprayTests(target, port, probes).Wait();
        }
    }

    static async Task RunTcpSprayTests(string target, int port, int probes)
    {
        Console.WriteLine($"\nRunning TCP Spray (Reliability Test) with {probes} probes...");
        var tester = new TcpSprayTester(target, port);
        
        // Default: 100ms interval
        var result = await tester.RunSprayAsync(probes, 100);
        
        PrintResult("TCP Spray", result.Success, result.Message, 0);
        if (result.Success)
        {
            Console.WriteLine($"    Sent: {result.Sent}, Received: {result.Received}");
            Console.WriteLine($"    Loss: {result.LossPercentage:F1}%");
            Console.WriteLine($"    Latency (ms): Min={result.MinLatency}, Max={result.MaxLatency}, Avg={result.AvgLatency}");
            Console.WriteLine($"    Jitter: {result.Jitter}ms");
        }
    }

    static async Task RunConnectivityTests(string target, int port)
    {
        Console.WriteLine("Running Connectivity Tests...");
        var tester = new ConnectivityTester(target, port);

        // Resolve IPs to check for Dual Stack
        IPAddress[] ips = Array.Empty<IPAddress>();
        try
        {
            ips = await Dns.GetHostAddressesAsync(target);
            Console.WriteLine($"    Resolved {ips.Length} IP(s): {string.Join(", ", ips.Select(i => i.ToString()))}");
        }
        catch
        {
            Console.WriteLine("    [WARN] Could not resolve target to specific IPs for dual-stack testing.");
        }

        // TCP Test (Default)
        var tcpResult = await tester.TestTcpConnectionAsync();
        PrintResult("TCP Connect (Default)", tcpResult.Success, tcpResult.Message, tcpResult.LatencyMs);

        // Dual Stack TCP Tests
        if (ips.Length > 0)
        {
            var v4 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var v6 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

            if (v4 != null)
            {
                var v4Result = await tester.TestTcpConnectionAsync(v4);
                PrintResult($"TCP Connect (IPv4: {v4})", v4Result.Success, v4Result.Message, v4Result.LatencyMs);
            }
            if (v6 != null)
            {
                var v6Result = await tester.TestTcpConnectionAsync(v6);
                PrintResult($"TCP Connect (IPv6: {v6})", v6Result.Success, v6Result.Message, v6Result.LatencyMs);
            }
        }

        // UDP Test
        var udpResult = await tester.TestUdpReachabilityAsync();
        PrintResult("UDP Reachability", udpResult.Success, udpResult.Message, udpResult.LatencyMs);
    }

    static async Task RunProtocolTests(string target, int port)
    {
        Console.WriteLine("\nRunning Protocol Analysis...");
        var tester = new ProtocolTester(target, port);

        // HTTP/3
        var http3Result = await tester.TestHttp3SupportAsync();
        PrintResult("HTTP/3 Support", http3Result.Success, http3Result.Message, 0);
        foreach(var kvp in http3Result.Details) Console.WriteLine($"    {kvp.Key}: {kvp.Value}");

        // TLS (Default)
        var tlsResult = await tester.AnalyzeTlsAsync();
        PrintResult("TLS Analysis (Default)", tlsResult.Success, tlsResult.Message, 0);
        foreach(var kvp in tlsResult.Details) Console.WriteLine($"    {kvp.Key}: {kvp.Value}");

        // Dual Stack TLS
        try
        {
            var ips = await Dns.GetHostAddressesAsync(target);
            var v4 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var v6 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

            if (v4 != null)
            {
                var v4Result = await tester.AnalyzeTlsAsync(v4);
                PrintResult($"TLS Analysis (IPv4: {v4})", v4Result.Success, v4Result.Message, 0);
            }
            if (v6 != null)
            {
                var v6Result = await tester.AnalyzeTlsAsync(v6);
                PrintResult($"TLS Analysis (IPv6: {v6})", v6Result.Success, v6Result.Message, 0);
            }
        }
        catch { /* Ignore DNS errors here, already reported in Connectivity */ }
    }

    static async Task RunIntelligenceTests(string target)
    {
        Console.WriteLine("\nRunning Network Intelligence...");
        
        // In a real app, we'd use Dependency Injection here
        using var httpClient = new HttpClient();
        var provider = new IpInfoProvider(httpClient);
        var tester = new NetworkIntelligenceTester(target, provider);

        var result = await tester.RunAsnLookupAsync();
        PrintResult("ASN/GeoIP Lookup", result.Success, result.Message, 0);
        foreach(var kvp in result.Data) Console.WriteLine($"    {kvp.Key}: {kvp.Value}");

        // Whois
        Console.WriteLine("    Running WHOIS Lookup...");
        var whois = new WhoisProvider();
        var whoisData = await whois.LookupAsync(target);
        // Truncate for display if too long
        var displayWhois = whoisData.Length > 500 ? whoisData.Substring(0, 500) + "... [Truncated]" : whoisData;
        Console.WriteLine($"    WHOIS Data:\n{displayWhois}");
    }

    static async Task RunPerformanceTests(string target, string downloadUrl)
    {
        Console.WriteLine("\nRunning Performance Tests...");
        var tester = new PerformanceTester(target);

        // Latency
        var latencyResult = await tester.TestLatencyAsync();
        PrintResult("Latency (Ping)", latencyResult.Success, latencyResult.Message, 0);
        if (latencyResult.Success) Console.WriteLine($"    Value: {latencyResult.Value} {latencyResult.Unit}");

        // Bandwidth
        if (!string.IsNullOrEmpty(downloadUrl))
        {
            var bandwidthResult = await tester.TestBandwidthAsync(downloadUrl);
            PrintResult("Bandwidth (Download)", bandwidthResult.Success, bandwidthResult.Message, 0);
            if (bandwidthResult.Success) Console.WriteLine($"    Speed: {bandwidthResult.Value} {bandwidthResult.Unit}");
        }
        else
        {
            Console.WriteLine("    [INFO] Skipping Bandwidth test (no --download-url provided).");
        }
    }

    static async Task RunAdvancedTests(string target)
    {
        Console.WriteLine("\nRunning Advanced Network Tests...");
        var tester = new AdvancedNetworkTester(target);

        // Traceroute
        Console.WriteLine("    [Traceroute]");
        var trace = await tester.RunTracerouteAsync();
        foreach (var hop in trace) Console.WriteLine($"    {hop}");

        // PMTU
        Console.WriteLine("    [Path MTU Discovery]");
        var pmtu = await tester.DiscoverPathMtuAsync();
        Console.WriteLine($"    {pmtu}");

        // Port Scan (Common Ports)
        Console.WriteLine("    [Port Scan - Top 20 Common Ports]");
        var commonPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443 };
        var openPorts = await tester.ScanPortsAsync(commonPorts);
        foreach (var p in openPorts) Console.WriteLine($"    {p}");
    }

    static async Task RunJa4Tests(string target, int port, string alpn)
    {
        Console.WriteLine("\nRunning JA4 Fingerprinting...");
        var tester = new Ja4Tester(target, port);
        
        List<SslApplicationProtocol>? alpnProtocols = null;
        if (!string.IsNullOrEmpty(alpn))
        {
            alpnProtocols = new List<SslApplicationProtocol>();
            foreach (var p in alpn.Split(','))
            {
                alpnProtocols.Add(new SslApplicationProtocol(p.Trim()));
            }
            Console.WriteLine($"    [INFO] Using explicit ALPN: {string.Join(", ", alpnProtocols.Select(p => p.ToString()))}");
        }

        // Default
        var result = await tester.CalculateJa4SAsync(null, alpnProtocols);
        PrintResult("JA4S (Server - Default)", result.Success, result.Message, 0);
        if (result.Success)
        {
            Console.WriteLine($"    Fingerprint: {result.Ja4S}");
            Console.WriteLine($"    Details: {result.RawDetails}");
        }

        // Dual Stack
        try
        {
            var ips = await Dns.GetHostAddressesAsync(target);
            var v4 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var v6 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

            if (v4 != null)
            {
                var v4Result = await tester.CalculateJa4SAsync(v4, alpnProtocols);
                PrintResult($"JA4S (IPv4: {v4})", v4Result.Success, v4Result.Message, 0);
                if (v4Result.Success) Console.WriteLine($"    Fingerprint: {v4Result.Ja4S}");
            }
            if (v6 != null)
            {
                var v6Result = await tester.CalculateJa4SAsync(v6, alpnProtocols);
                PrintResult($"JA4S (IPv6: {v6})", v6Result.Success, v6Result.Message, 0);
                if (v6Result.Success) Console.WriteLine($"    Fingerprint: {v6Result.Ja4S}");
            }
        }
        catch { }

        // HTTP/3 (QUIC)
        Console.WriteLine("\n    [HTTP/3 QUIC Analysis]");
        var h3Result = await tester.CalculateJa4H3Async();
        PrintResult("JA4 (QUIC)", h3Result.Success, h3Result.Message, 0);
        if (h3Result.Success)
        {
            Console.WriteLine($"    Fingerprint: {h3Result.Ja4S}");
            Console.WriteLine($"    Details: {h3Result.RawDetails}");
        }
    }

    static void PrintResult(string testName, bool success, string message, long latencyMs)
    {
        var status = success ? "[PASS]" : "[FAIL]";
        var color = success ? ConsoleColor.Green : ConsoleColor.Red;
        
        Console.ForegroundColor = color;
        Console.Write(status);
        Console.ResetColor();
        
        if (latencyMs > 0)
            Console.WriteLine($" {testName}: {message} ({latencyMs}ms)");
        else
            Console.WriteLine($" {testName}: {message}");
    }
}