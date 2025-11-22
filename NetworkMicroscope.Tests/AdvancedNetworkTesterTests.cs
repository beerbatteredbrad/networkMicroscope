using NetworkMicroscope.Core;
using System.Net;
using System.Net.Sockets;

namespace NetworkMicroscope.Tests;

public class AdvancedNetworkTesterTests
{
    [Fact]
    public void Top100Ports_ShouldContainCommonPorts()
    {
        Assert.Contains(80, AdvancedNetworkTester.Top100Ports);
        Assert.Contains(443, AdvancedNetworkTester.Top100Ports);
        Assert.Contains(22, AdvancedNetworkTester.Top100Ports);
        Assert.True(AdvancedNetworkTester.Top100Ports.Length >= 100);
    }

    [Fact]
    public async Task ScanPortsAsync_ShouldFindOpenPorts()
    {
        // Arrange
        // We'll scan google.com on 80 and 443, which should be open.
        // And a random high port that should be closed/filtered.
        var tester = new AdvancedNetworkTester("google.com");
        var ports = new[] { 80, 443, 55555 };

        // Act
        var results = await tester.ScanPortsAsync(ports);

        // Assert
        Assert.Contains(results, r => r.Contains("Port 80: OPEN"));
        Assert.Contains(results, r => r.Contains("Port 443: OPEN"));
        // We don't assert on 55555 because it just won't be in the list (or list will be empty if none found)
        // But since we expect 80/443 to be found, the list shouldn't be empty.
        Assert.NotEmpty(results);
    }
}
