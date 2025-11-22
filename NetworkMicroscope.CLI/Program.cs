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
        string portsArg = "";

        // Simple manual parsing for now (can use System.CommandLine later)
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--target" && i + 1 < args.Length) target = args[i + 1];
            if (args[i] == "--port" && i + 1 < args.Length) int.TryParse(args[i + 1], out port);
            if (args[i] == "--test" && i + 1 < args.Length) testType = args[i + 1];
            if (args[i] == "--download-url" && i + 1 < args.Length) downloadUrl = args[i + 1];
            if (args[i] == "--probes" && i + 1 < args.Length) int.TryParse(args[i + 1], out probes);
            if (args[i] == "--alpn" && i + 1 < args.Length) alpn = args[i + 1];
            if (args[i] == "--ports" && i + 1 < args.Length) portsArg = args[i + 1];
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
            RunAdvancedTests(target, portsArg).Wait();
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

    static void PrintSectionHeader(string title)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("==================================================");
        Console.WriteLine($" {title}");
        Console.WriteLine("==================================================");
        Console.ResetColor();
    }

    static async Task RunTcpSprayTests(string target, int port, int probes)
    {
        PrintSectionHeader($"Running TCP Spray (Reliability Test) with {probes} probes...");
        var tester = new TcpSprayTester(target, port);
        
        // Adjust delay for larger sprays to keep runtime reasonable
        // 100 probes @ 50ms = 5s
        // 1000 probes @ 10ms = 10s
        int delay = probes > 200 ? 10 : 50;

        var progress = new Progress<(int completed, int total)>(update => 
        {
            DrawProgressBar(update.completed, update.total);
        });

        var result = await tester.RunSprayAsync(probes, delay, progress);
        
        Console.WriteLine(); // Move to next line after progress bar completes
        PrintResult("TCP Spray", result.Success, result.Message, 0);
        if (result.Success)
        {
            Console.WriteLine($"    Sent: {result.Sent}, Received: {result.Received}");
            Console.WriteLine($"    Loss: {result.LossPercentage:F1}%");
            Console.WriteLine($"    Latency (ms): Min={result.MinLatency}, Max={result.MaxLatency}, Avg={result.AvgLatency}");
            Console.WriteLine($"    Jitter: {result.Jitter}ms");
        }
    }

    static void DrawProgressBar(int completed, int total)
    {
        if (total == 0) return;
        
        int width = 40;
        double percent = (double)completed / total;
        int filled = (int)(percent * width);
        
        // \r overwrites the current line
        Console.Write($"\r    Progress: [{new string('=', filled)}{new string(' ', width - filled)}] {percent:P0} ({completed}/{total})");
    }

    static async Task RunConnectivityTests(string target, int port)
    {
        PrintSectionHeader("Running Connectivity Tests...");
        var tester = new ConnectivityTester(target, port);

        // Start generic tasks immediately
        var tcpDefaultTask = tester.TestTcpConnectionAsync();
        var udpTask = tester.TestUdpReachabilityAsync();

        // Resolve IPs for Dual Stack
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

        // Start IP-specific tasks
        Task<ConnectivityResult>? v4Task = null;
        Task<ConnectivityResult>? v6Task = null;
        IPAddress? v4 = null;
        IPAddress? v6 = null;

        if (ips.Length > 0)
        {
            v4 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            v6 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

            if (v4 != null) v4Task = tester.TestTcpConnectionAsync(v4);
            if (v6 != null) v6Task = tester.TestTcpConnectionAsync(v6);
        }

        // Await and Print in order
        var tcpResult = await tcpDefaultTask;
        PrintResult("TCP Connect (Default)", tcpResult.Success, tcpResult.Message, tcpResult.LatencyMs);

        if (v4Task != null)
        {
            var v4Result = await v4Task;
            PrintResult($"TCP Connect (IPv4: {v4})", v4Result.Success, v4Result.Message, v4Result.LatencyMs);
        }

        if (v6Task != null)
        {
            var v6Result = await v6Task;
            PrintResult($"TCP Connect (IPv6: {v6})", v6Result.Success, v6Result.Message, v6Result.LatencyMs);
        }

        var udpResult = await udpTask;
        PrintResult("UDP Reachability", udpResult.Success, udpResult.Message, udpResult.LatencyMs);
    }

    static async Task RunProtocolTests(string target, int port)
    {
        PrintSectionHeader("Running Protocol Analysis...");
        var tester = new ProtocolTester(target, port);

        // Prepare tasks
        var http3Task = tester.TestHttp3SupportAsync();
        var tlsDefaultTask = tester.AnalyzeTlsAsync();
        
        Task<ProtocolResult>? v4Task = null;
        Task<ProtocolResult>? v6Task = null;

        IPAddress? v4 = null;
        IPAddress? v6 = null;

        try
        {
            var ips = await Dns.GetHostAddressesAsync(target);
            v4 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            v6 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

            if (v4 != null) v4Task = tester.AnalyzeTlsAsync(v4);
            if (v6 != null) v6Task = tester.AnalyzeTlsAsync(v6);
        }
        catch { }

        // Print HTTP/3
        var http3Result = await http3Task;
        PrintResult("HTTP/3 Support", http3Result.Success, http3Result.Message, 0);
        foreach(var kvp in http3Result.Details) Console.WriteLine($"    {kvp.Key}: {kvp.Value}");

        // Print TLS Default
        var tlsResult = await tlsDefaultTask;
        PrintResult("TLS Analysis (Default)", tlsResult.Success, tlsResult.Message, 0);
        foreach(var kvp in tlsResult.Details) Console.WriteLine($"    {kvp.Key}: {kvp.Value}");

        // Print Dual Stack TLS
        if (v4Task != null)
        {
            var v4Result = await v4Task;
            PrintResult($"TLS Analysis (IPv4: {v4})", v4Result.Success, v4Result.Message, 0);
        }
        if (v6Task != null)
        {
            var v6Result = await v6Task;
            PrintResult($"TLS Analysis (IPv6: {v6})", v6Result.Success, v6Result.Message, 0);
        }
    }

    static async Task RunIntelligenceTests(string target)
    {
        PrintSectionHeader("Running Network Intelligence...");
        
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
        PrintSectionHeader("Running Performance Tests...");
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

    static async Task RunAdvancedTests(string target, string portsArg)
    {
        PrintSectionHeader("Running Advanced Network Tests...");
        var tester = new AdvancedNetworkTester(target);

        // Traceroute
        Console.WriteLine("    [Traceroute]");
        var trace = await tester.RunTracerouteAsync();
        foreach (var hop in trace) Console.WriteLine($"    {hop}");

        // PMTU
        Console.WriteLine("    [Path MTU Discovery]");
        var pmtu = await tester.DiscoverPathMtuAsync();
        Console.WriteLine($"    {pmtu}");

        // Port Scan
        var portsToScan = ParsePorts(portsArg).ToList();
        Console.WriteLine($"    [Port Scan - Scanning {portsToScan.Count} ports]");
        
        var openPorts = await tester.ScanPortsAsync(portsToScan);
        foreach (var p in openPorts) Console.WriteLine($"    {p}");
    }

    static IEnumerable<int> ParsePorts(string portsArg)
    {
        if (string.IsNullOrWhiteSpace(portsArg))
            return AdvancedNetworkTester.Top100Ports;

        var ports = new HashSet<int>();
        var parts = portsArg.Split(',');

        foreach (var part in parts)
        {
            if (part.Contains('-'))
            {
                var range = part.Split('-');
                if (range.Length == 2 && int.TryParse(range[0], out int start) && int.TryParse(range[1], out int end))
                {
                    for (int i = start; i <= end; i++) ports.Add(i);
                }
            }
            else
            {
                if (int.TryParse(part, out int p)) ports.Add(p);
            }
        }
        return ports.OrderBy(p => p);
    }

    static async Task RunJa4Tests(string target, int port, string alpn)
    {
        PrintSectionHeader("Running JA4 Fingerprinting...");
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

        // Prepare tasks
        var defaultTask = tester.CalculateJa4SAsync(null, alpnProtocols);
        var h3Task = tester.CalculateJa4H3Async();
        
        Task<Ja4Result>? v4Task = null;
        Task<Ja4Result>? v6Task = null;
        IPAddress? v4 = null;
        IPAddress? v6 = null;

        try
        {
            var ips = await Dns.GetHostAddressesAsync(target);
            v4 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            v6 = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

            if (v4 != null) v4Task = tester.CalculateJa4SAsync(v4, alpnProtocols);
            if (v6 != null) v6Task = tester.CalculateJa4SAsync(v6, alpnProtocols);
        }
        catch { }

        // Print Default
        var result = await defaultTask;
        PrintResult("JA4S (Server - Default)", result.Success, result.Message, 0);
        if (result.Success)
        {
            Console.WriteLine($"    Fingerprint: {result.Ja4S}");
            Console.WriteLine($"    Details: {result.RawDetails}");
        }

        // Print Dual Stack
        if (v4Task != null)
        {
            var v4Result = await v4Task;
            PrintResult($"JA4S (IPv4: {v4})", v4Result.Success, v4Result.Message, 0);
            if (v4Result.Success) Console.WriteLine($"    Fingerprint: {v4Result.Ja4S}");
        }
        if (v6Task != null)
        {
            var v6Result = await v6Task;
            PrintResult($"JA4S (IPv6: {v6})", v6Result.Success, v6Result.Message, 0);
            if (v6Result.Success) Console.WriteLine($"    Fingerprint: {v6Result.Ja4S}");
        }

        // Print HTTP/3
        Console.WriteLine("\n    [HTTP/3 QUIC Analysis]");
        var h3Result = await h3Task;
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