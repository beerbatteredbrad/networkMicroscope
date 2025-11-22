using Moq;
using NetworkMicroscope.Core;
using Xunit;

namespace NetworkMicroscope.Tests;

public class NetworkIntelligenceTests
{
    [Fact]
    public async Task RunAsnLookupAsync_ReturnsSuccess_WhenProviderSucceeds()
    {
        // Arrange
        string target = "8.8.8.8";
        var mockProvider = new Mock<INetworkIntelligenceProvider>();
        
        var expectedResult = new IntelligenceResult 
        { 
            Success = true, 
            Message = "OK",
            Data = new Dictionary<string, string> { { "org", "Google LLC" }, { "country", "US" } }
        };

        mockProvider.Setup(p => p.GetAsnInfoAsync(target))
                    .ReturnsAsync(expectedResult);

        var tester = new NetworkIntelligenceTester(target, mockProvider.Object);

        // Act
        var result = await tester.RunAsnLookupAsync();

        // Assert
        Assert.True(result.Success);
        Assert.Equal("Google LLC", result.Data["org"]);
        mockProvider.Verify(p => p.GetAsnInfoAsync(target), Times.Once);
    }

    [Fact]
    public async Task RunAsnLookupAsync_ResolvesDomainToIp()
    {
        // Arrange
        string domain = "google.com";
        // We can't easily mock Dns.GetHostAddressesAsync without a wrapper, 
        // so this test relies on the fact that the Tester logic attempts resolution.
        // However, since we can't predict the exact IP google.com resolves to in a unit test,
        // we verify that the provider is called with *some* IP, not the domain string.
        
        var mockProvider = new Mock<INetworkIntelligenceProvider>();
        mockProvider.Setup(p => p.GetAsnInfoAsync(It.IsAny<string>()))
                    .ReturnsAsync(new IntelligenceResult { Success = true });

        var tester = new NetworkIntelligenceTester(domain, mockProvider.Object);

        // Act
        await tester.RunAsnLookupAsync();

        // Assert
        // Verify that GetAsnInfoAsync was called with a string that is NOT "google.com"
        // implying some resolution happened (or at least it tried).
        // Note: If DNS fails, it falls back to original string, so this test assumes DNS works.
        mockProvider.Verify(p => p.GetAsnInfoAsync(It.Is<string>(s => s != domain)), Times.Once);
    }
}