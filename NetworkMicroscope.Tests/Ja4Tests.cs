using Moq;
using NetworkMicroscope.Core;
using Xunit;

namespace NetworkMicroscope.Tests;

public class Ja4Tests
{
    [Fact]
    public void ParseServerHello_ReturnsCorrectJa4S_ForTls13()
    {
        // Arrange
        var tester = new Ja4Tester("localhost", 443);
        
        // Construct a fake ServerHello buffer
        // Record Header (5) + Handshake Header (4) + Body
        var buffer = new List<byte>();
        
        // Record Header
        buffer.Add(0x16); // Handshake
        buffer.Add(0x03); buffer.Add(0x03); // TLS 1.2 (Record)
        buffer.Add(0x00); buffer.Add(0x00); // Len placeholder (pos 3)

        // Handshake Header
        buffer.Add(0x02); // ServerHello
        buffer.Add(0x00); buffer.Add(0x00); buffer.Add(0x00); // Len placeholder (pos 7)

        // Body
        // Version (TLS 1.2 legacy)
        buffer.Add(0x03); buffer.Add(0x03);
        
        // Random (32)
        buffer.AddRange(new byte[32]);
        
        // Session ID (0)
        buffer.Add(0x00);
        
        // Cipher (0x1301 - TLS_AES_128_GCM_SHA256)
        buffer.Add(0x13); buffer.Add(0x01);
        
        // Compression (0)
        buffer.Add(0x00);
        
        // Extensions
        var extBuffer = new List<byte>();
        
        // Supported Versions (0x002b) -> TLS 1.3 (0x0304)
        extBuffer.Add(0x00); extBuffer.Add(0x2b); // Type
        extBuffer.Add(0x00); extBuffer.Add(0x02); // Len
        extBuffer.Add(0x03); extBuffer.Add(0x04); // TLS 1.3

        // ALPN (0x0010) -> h2
        extBuffer.Add(0x00); extBuffer.Add(0x10); // Type
        extBuffer.Add(0x00); extBuffer.Add(0x05); // Len
        extBuffer.Add(0x00); extBuffer.Add(0x03); // List Len
        extBuffer.Add(0x02); // Proto Len
        extBuffer.AddRange(System.Text.Encoding.ASCII.GetBytes("h2"));

        // Add Ext Len
        buffer.Add((byte)(extBuffer.Count >> 8));
        buffer.Add((byte)(extBuffer.Count & 0xFF));
        buffer.AddRange(extBuffer);

        // Act
        var result = tester.ParseServerHello(buffer.ToArray(), buffer.Count);

        // Assert
        Assert.True(result.Success);
        // Expected: t13h2_1301_<hash>
        Assert.StartsWith("t13h2_1301_", result.Ja4S);
    }

    [Fact]
    public void ParseServerHello_ReturnsCorrectJa4S_ForTls12()
    {
        // Arrange
        var tester = new Ja4Tester("localhost", 443);
        var buffer = new List<byte>();
        
        // Record Header
        buffer.Add(0x16); buffer.Add(0x03); buffer.Add(0x03); buffer.Add(0x00); buffer.Add(0x00);
        // Handshake Header
        buffer.Add(0x02); buffer.Add(0x00); buffer.Add(0x00); buffer.Add(0x00);
        // Body
        buffer.Add(0x03); buffer.Add(0x03); // TLS 1.2
        buffer.AddRange(new byte[32]); // Random
        buffer.Add(0x00); // Session ID
        buffer.Add(0xC0); buffer.Add(0x2F); // Cipher (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        buffer.Add(0x00); // Compression

        // Extensions
        var extBuffer = new List<byte>();
        // ALPN -> http/1.1
        extBuffer.Add(0x00); extBuffer.Add(0x10);
        extBuffer.Add(0x00); extBuffer.Add(0x0B); // Len
        extBuffer.Add(0x00); extBuffer.Add(0x09); // List Len
        extBuffer.Add(0x08); // Proto Len
        extBuffer.AddRange(System.Text.Encoding.ASCII.GetBytes("http/1.1"));

        buffer.Add((byte)(extBuffer.Count >> 8));
        buffer.Add((byte)(extBuffer.Count & 0xFF));
        buffer.AddRange(extBuffer);

        // Act
        var result = tester.ParseServerHello(buffer.ToArray(), buffer.Count);

        // Assert
        Assert.True(result.Success);
        // Expected: t12h1_c02f_<hash>
        Assert.StartsWith("t12h1_c02f_", result.Ja4S);
    }

    [Fact]
    public void ParseServerHello_HandlesNoExtensions()
    {
        // Arrange
        var tester = new Ja4Tester("localhost", 443);
        var buffer = new List<byte>();
        
        buffer.Add(0x16); buffer.Add(0x03); buffer.Add(0x03); buffer.Add(0x00); buffer.Add(0x00);
        buffer.Add(0x02); buffer.Add(0x00); buffer.Add(0x00); buffer.Add(0x00);
        buffer.Add(0x03); buffer.Add(0x03); // TLS 1.2
        buffer.AddRange(new byte[32]);
        buffer.Add(0x00);
        buffer.Add(0x00); buffer.Add(0x35); // Cipher (TLS_RSA_WITH_AES_256_CBC_SHA)
        buffer.Add(0x00);
        
        // No Extensions (Length 0)
        buffer.Add(0x00); buffer.Add(0x00);

        // Act
        var result = tester.ParseServerHello(buffer.ToArray(), buffer.Count);

        // Assert
        Assert.True(result.Success);
        // Expected: t1200_0035_0000 (0000 is hash for no extensions)
        Assert.Equal("t1200_0035_0000", result.Ja4S);
    }

    [Fact]
    public void ParseServerHello_ReturnsError_ForInvalidHandshake()
    {
        var tester = new Ja4Tester("localhost", 443);
        byte[] buffer = new byte[] { 0x00, 0x01, 0x02 }; // Garbage
        
        var result = tester.ParseServerHello(buffer, 3);
        
        Assert.False(result.Success);
        Assert.Equal("Not a TLS Handshake.", result.Message);
    }
}