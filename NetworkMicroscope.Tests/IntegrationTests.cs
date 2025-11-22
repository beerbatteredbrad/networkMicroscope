using NetworkMicroscope.Core;
using Xunit;

namespace NetworkMicroscope.Tests;

public class IntegrationTests
{
    private const string TestTarget = "google.com";
    private const int TestPort = 443;

    [Fact]
    public async Task ConnectivityTester_TcpConnect_SucceedsForGoogle()
    {
        var tester = new ConnectivityTester(TestTarget, TestPort);
        var result = await tester.TestTcpConnectionAsync();
        
        Assert.True(result.Success, $"TCP Connect failed: {result.Message}");
        Assert.True(result.LatencyMs >= 0);
    }

    [Fact]
    public async Task ProtocolTester_AnalyzeTls_SucceedsForGoogle()
    {
        var tester = new ProtocolTester(TestTarget, TestPort);
        var result = await tester.AnalyzeTlsAsync();

        Assert.True(result.Success, $"TLS Analysis failed: {result.Message}");
        Assert.Contains("Protocol", result.Details);
        Assert.Contains("CipherSuite", result.Details);
    }

    [Fact]
    public async Task PerformanceTester_TestLatency_SucceedsForGoogle()
    {
        var tester = new PerformanceTester(TestTarget);
        var result = await tester.TestLatencyAsync();

        Assert.True(result.Success, $"Latency test failed: {result.Message}");
        Assert.True(result.Value > 0);
    }

    [Fact]
    public async Task AdvancedNetworkTester_ScanPorts_FindsOpenPort()
    {
        var tester = new AdvancedNetworkTester(TestTarget);
        var ports = new[] { 80, 443 };
        
        var results = await tester.ScanPortsAsync(ports);
        
        Assert.NotEmpty(results);
        Assert.Contains(results, r => r.Contains("OPEN"));
    }

    [Fact]
    public async Task Ja4Tester_CalculateJa4S_ReturnsValidFingerprint()
    {
        var tester = new Ja4Tester(TestTarget, TestPort);
        var result = await tester.CalculateJa4SAsync();

        Assert.True(result.Success, $"JA4S calculation failed: {result.Message}");
        Assert.False(string.IsNullOrEmpty(result.Ja4S));
        // JA4S format: t<ver><alpn>_<cipher>_<hash> (e.g., t1300_1302_c35a6cc4faa0)
        Assert.Matches(@"^t\d{2}[a-z0-9]{2}_[a-f0-9]{4}_[a-f0-9]{12}$", result.Ja4S);
    }

    [Fact]
    public async Task TcpSprayTester_RunSpray_SucceedsForGoogle()
    {
        var tester = new TcpSprayTester(TestTarget, TestPort);
        // Run a small spray (5 probes) to be quick
        var result = await tester.RunSprayAsync(5, 50);

        Assert.True(result.Success, $"TCP Spray failed: {result.Message}");
        Assert.Equal(5, result.Sent);
        Assert.True(result.Received > 0, "Should receive at least one response from Google");
        Assert.True(result.AvgLatency > 0);
    }
}
