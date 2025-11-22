using NetworkMicroscope.Core;
using System.Net;
using System.Net.Sockets;

namespace NetworkMicroscope.Tests;

public class AdvancedNetworkTesterTests
{
    [Fact]
    public void Top100Ports_ShouldContainCommonPorts()
    {
        Assert.Contains(20, AdvancedNetworkTester.Top100Ports); // FTP Data
        Assert.Contains(21, AdvancedNetworkTester.Top100Ports); // FTP Control
        Assert.Contains(22, AdvancedNetworkTester.Top100Ports); // SSH
        Assert.Contains(23, AdvancedNetworkTester.Top100Ports); // Telnet
        Assert.Contains(25, AdvancedNetworkTester.Top100Ports); // SMTP
        Assert.Contains(53, AdvancedNetworkTester.Top100Ports); // DNS
        Assert.Contains(80, AdvancedNetworkTester.Top100Ports); // HTTP
        Assert.Contains(110, AdvancedNetworkTester.Top100Ports); // POP3
        Assert.Contains(143, AdvancedNetworkTester.Top100Ports); // IMAP
        Assert.Contains(443, AdvancedNetworkTester.Top100Ports); // HTTPS
        Assert.Contains(3389, AdvancedNetworkTester.Top100Ports); // RDP
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
