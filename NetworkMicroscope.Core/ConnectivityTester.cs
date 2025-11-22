using System.Net;
using System.Net.Sockets;
using System.Diagnostics;

namespace NetworkMicroscope.Core;

public class ConnectivityResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public long LatencyMs { get; set; }
}

public class ConnectivityTester
{
    private readonly string _target;
    private readonly int _port;

    public ConnectivityTester(string target, int port)
    {
        _target = target;
        _port = port;
    }

    public async Task<ConnectivityResult> TestTcpConnectionAsync()
    {
        var result = new ConnectivityResult();
        var stopwatch = new Stopwatch();

        try
        {
            using var client = new TcpClient();
            stopwatch.Start();
            
            // ConnectAsync with a timeout is often better, but for simplicity we use the standard call
            // We can add a cancellation token or timeout wrapper later if needed.
            var connectTask = client.ConnectAsync(_target, _port);
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(5));

            var completedTask = await Task.WhenAny(connectTask, timeoutTask);

            stopwatch.Stop();
            result.LatencyMs = stopwatch.ElapsedMilliseconds;

            if (completedTask == timeoutTask)
            {
                result.Success = false;
                result.Message = $"TCP Connection to {_target}:{_port} timed out after 5 seconds.";
            }
            else
            {
                // Propagate any exceptions from ConnectAsync
                await connectTask; 
                result.Success = true;
                result.Message = $"Successfully connected to {_target}:{_port} via TCP.";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"TCP Connection failed: {ex.Message}";
        }

        return result;
    }

    public async Task<ConnectivityResult> TestTcpConnectionAsync(IPAddress ip)
    {
        var result = new ConnectivityResult();
        var stopwatch = new Stopwatch();

        try
        {
            using var client = new TcpClient(ip.AddressFamily); // Ensure correct address family
            stopwatch.Start();
            
            var connectTask = client.ConnectAsync(ip, _port);
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(2));

            var completedTask = await Task.WhenAny(connectTask, timeoutTask);

            stopwatch.Stop();
            result.LatencyMs = stopwatch.ElapsedMilliseconds;

            if (completedTask == timeoutTask)
            {
                result.Success = false;
                result.Message = $"TCP Connection to {ip}:{_port} timed out after 2 seconds.";
            }
            else
            {
                await connectTask; 
                result.Success = true;
                result.Message = $"Successfully connected to {ip}:{_port} via TCP.";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"TCP Connection to {ip} failed: {ex.Message}";
        }

        return result;
    }

    public async Task<ConnectivityResult> TestUdpReachabilityAsync()
    {
        // UDP is connectionless, so "reachability" is harder to prove without a protocol response.
        // We will try to send a dummy packet. If we get an ICMP Port Unreachable, we know it's closed.
        // If we get nothing, it might be open or filtered.
        // NOTE: This is a basic check. True UDP verification requires an application-layer handshake.

        var result = new ConnectivityResult();
        var stopwatch = new Stopwatch();

        try
        {
            using var udpClient = new UdpClient();
            udpClient.Client.ReceiveTimeout = 2000; // 2 seconds
            
            // Connect establishes a default remote host, it doesn't actually send packets yet for UDP
            udpClient.Connect(_target, _port);

            byte[] sendBytes = [0x01, 0x02, 0x03, 0x04]; // Dummy payload
            
            stopwatch.Start();
            await udpClient.SendAsync(sendBytes, sendBytes.Length);
            stopwatch.Stop();

            // In many cases, we won't get a response unless the server speaks a specific protocol.
            // We assume "Success" means we could send the packet without immediate OS error.
            result.Success = true;
            result.Message = $"UDP Packet sent to {_target}:{_port}. (Note: UDP is connectionless; lack of error implies reachability or silent drop).";
            result.LatencyMs = stopwatch.ElapsedMilliseconds;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"UDP Send failed: {ex.Message}";
        }

        return result;
    }
}