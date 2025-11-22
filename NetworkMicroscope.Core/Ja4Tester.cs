using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace NetworkMicroscope.Core;

public class Ja4Result
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string Ja4S { get; set; } = string.Empty; // JA4S is for Server
    public string RawDetails { get; set; } = string.Empty;
}

public class Ja4Tester
{
    private readonly string _target;
    private readonly int _port;

    public Ja4Tester(string target, int port)
    {
        _target = target;
        _port = port;
    }

    public async Task<Ja4Result> CalculateJa4SAsync(IPAddress? specificIp = null)
    {
        var result = new Ja4Result();
        try
        {
            using var client = new TcpClient();
            Task connectTask;
            int timeoutSeconds = 5;

            if (specificIp != null)
            {
                connectTask = client.ConnectAsync(specificIp, _port);
                timeoutSeconds = 2;
            }
            else
            {
                connectTask = client.ConnectAsync(_target, _port);
            }

            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(timeoutSeconds));
            var completedTask = await Task.WhenAny(connectTask, timeoutTask);

            if (completedTask == timeoutTask)
            {
                result.Success = false;
                result.Message = $"Connection timed out after {timeoutSeconds} seconds.";
                return result;
            }
            await connectTask;
            using var networkStream = client.GetStream();

            // Wrap the network stream with our snooping stream
            using var snoopingStream = new TlsSnoopingStream(networkStream);

            // Use SslStream to perform the handshake
            // We don't validate the cert because we just want the handshake bytes
            using var sslStream = new SslStream(snoopingStream, false, (sender, cert, chain, errors) => true);

            try
            {
                await sslStream.AuthenticateAsClientAsync(_target);
            }
            catch
            {
                // Handshake might fail or complete, we just want the bytes
            }

            // Now analyze the captured bytes from the snooping stream
            var serverHelloBytes = snoopingStream.GetReadBytes();
            
            if (serverHelloBytes.Length < 5)
            {
                result.Success = false;
                result.Message = "No response or response too short.";
                return result;
            }

            // Find the ServerHello in the captured bytes
            // The captured bytes might contain multiple records. We need to find the Handshake record (0x16)
            // that contains the ServerHello (0x02).
            
            int serverHelloOffset = FindServerHelloOffset(serverHelloBytes);
            if (serverHelloOffset == -1)
            {
                 result.Success = false;
                 result.Message = "ServerHello not found in captured bytes.";
                 return result;
            }

            // 3. Parse ServerHello
            // We pass the buffer starting from the record header
            byte[] relevantBytes = new byte[serverHelloBytes.Length - serverHelloOffset];
            Array.Copy(serverHelloBytes, serverHelloOffset, relevantBytes, 0, relevantBytes.Length);
            
            return ParseServerHello(relevantBytes, relevantBytes.Length);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"JA4S Failed: {ex.Message}";
            return result;
        }
    }

    private int FindServerHelloOffset(byte[] buffer)
    {
        // Look for Record Type 0x16 (Handshake)
        for (int i = 0; i < buffer.Length - 5; i++)
        {
            if (buffer[i] == 0x16)
            {
                // Check version (major is usually 3)
                if (buffer[i+1] == 0x03)
                {
                    // Get Record Length
                    int recordLen = (buffer[i+3] << 8) | buffer[i+4];
                    
                    // Check if inside this record we have a ServerHello (0x02)
                    if (i + 5 < buffer.Length && buffer[i+5] == 0x02)
                    {
                        return i;
                    }
                    
                    // If the record is fragmented or multiple messages, we might need to look deeper,
                    // but usually ServerHello is the first message in the first response record.
                }
            }
        }
        return -1;
    }

    public Ja4Result ParseServerHello(byte[] buffer, int bytesRead)
    {
        var result = new Ja4Result();
        try
        {
            // Record Type (1 byte) + Version (2 bytes) + Length (2 bytes)
            if (buffer[0] != 0x16) // Handshake
            {
                result.Success = false;
                result.Message = "Not a TLS Handshake.";
                return result;
            }

            // Handshake Header: Type (1) + Length (3)
            int handshakeType = buffer[5];
            if (handshakeType != 0x02) // ServerHello
            {
                result.Success = false;
                result.Message = "Not a ServerHello.";
                return result;
            }

            // Parse ServerHello Body
            // Version (2) + Random (32) + SessionID Len (1) + SessionID (var) + Cipher (2) + Compression (1) + Ext Len (2) + Exts (var)
            
            int offset = 6 + 3; // Skip Record Header (5) + Handshake Type (1) + Handshake Len (3)
            
            // Server Version (2 bytes) - Note: TLS 1.3 often sends 0x0303 (TLS 1.2) here and puts 1.3 in extensions
            int serverVersionMajor = buffer[offset];
            int serverVersionMinor = buffer[offset + 1];
            offset += 2;

            offset += 32; // Random

            int sessionIdLen = buffer[offset];
            offset += 1 + sessionIdLen;

            // Cipher Suite (2 bytes)
            byte c1 = buffer[offset];
            byte c2 = buffer[offset + 1];
            string cipherHex = $"{c1:x2}{c2:x2}";
            offset += 2;

            offset += 1; // Compression Method

            // Extensions
            int extLen = (buffer[offset] << 8) | buffer[offset + 1];
            offset += 2;

            var extensions = new List<int>();
            int endOfExt = offset + extLen;
            
            // Scan extensions
            string alpn = "00";
            bool isTls13 = false;

            while (offset < endOfExt && offset + 4 <= bytesRead)
            {
                int extType = (buffer[offset] << 8) | buffer[offset + 1];
                int extDataLen = (buffer[offset + 2] << 8) | buffer[offset + 3];
                
                extensions.Add(extType);

                // Check for Supported Versions (0x002b) to detect TLS 1.3
                if (extType == 0x002b)
                {
                    // Parse supported version to see if it picked 1.3 (0x0304)
                    // Usually ServerHello Supported Version extension contains the selected version (2 bytes)
                    if (extDataLen >= 2)
                    {
                        int selectedVer = (buffer[offset + 4] << 8) | buffer[offset + 5];
                        if (selectedVer == 0x0304) isTls13 = true;
                    }
                }

                // Check for ALPN (0x0010)
                if (extType == 0x0010)
                {
                    // Parse ALPN to find selected protocol
                    // ALPN Ext Structure: List Len (2) + Proto Len (1) + Proto
                    if (extDataLen > 3)
                    {
                        int protoLen = buffer[offset + 6];
                        string proto = Encoding.ASCII.GetString(buffer, offset + 7, protoLen);
                        if (proto == "h2") alpn = "h2";
                        else if (proto == "http/1.1") alpn = "h1";
                        else if (proto == "h3") alpn = "h3";
                        else alpn = proto.Substring(0, 2); // Fallback
                    }
                }

                offset += 4 + extDataLen;
            }

            // Construct JA4S
            // JA4S = t<version><alpn>_<cipher>_<extensions_hash>
            
            string versionStr = isTls13 ? "13" : (serverVersionMinor == 3 ? "12" : "11"); // Simplified
            string protocolStr = "t"; // TCP

            // Part 1
            string part1 = $"{protocolStr}{versionStr}{alpn}";

            // Part 2: Cipher Hex (4 chars)
            string part2 = cipherHex;

            // Part 3: Extension Hash
            extensions.Sort();
            string extString = string.Join("_", extensions.Select(e => e.ToString("x4")));
            string part3 = ComputeSha256Prefix(extString);
            if (extensions.Count == 0) part3 = "0000";

            result.Success = true;
            result.Ja4S = $"{part1}_{part2}_{part3}";
            result.Message = "JA4S Calculated.";
            result.RawDetails = $"Ver: {versionStr}, Cipher: {cipherHex}, Exts: {extensions.Count}";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"Parsing Failed: {ex.Message}";
        }
        return result;
    }

    private string ComputeSha256Prefix(string input)
    {
        using var sha = SHA256.Create();
        byte[] bytes = Encoding.ASCII.GetBytes(input);
        byte[] hash = sha.ComputeHash(bytes);
        // Return first 12 chars of hex? JA4 uses 12 chars for the last part usually.
        return BitConverter.ToString(hash).Replace("-", "").ToLower().Substring(0, 12);
    }
}