using System.Net.Sockets;
using System.Text;

namespace NetworkMicroscope.Core;

public class WhoisProvider
{
    public async Task<string> LookupAsync(string query)
    {
        // Simple WHOIS client
        // 1. Connect to whois.iana.org to find the referral
        // 2. Connect to the referral server to get the details
        // For simplicity in this "Swiss-army knife", we might just query a major one like whois.arin.net for IPs 
        // or whois.verisign-grs.com for com/net, but IANA is the root.
        
        // Let's try a smart approach:
        // If it looks like an IP, query ARIN (North America) - it often redirects or informs.
        // If it looks like a domain, try IANA first.

        string server = "whois.iana.org";
        string response = await QueryWhoisServerAsync(server, query);

        // Parse referral
        var referralServer = ParseReferral(response);
        if (!string.IsNullOrEmpty(referralServer))
        {
            // Query the referral
            string referralResponse = await QueryWhoisServerAsync(referralServer, query);
            return $"--- Referral to {referralServer} ---\n{referralResponse}";
        }

        return response;
    }

    private async Task<string> QueryWhoisServerAsync(string server, string query)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(server, 43);

            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII);
            using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

            await writer.WriteLineAsync(query);
            
            return await reader.ReadToEndAsync();
        }
        catch (Exception ex)
        {
            return $"WHOIS Lookup failed on {server}: {ex.Message}";
        }
    }

    private string? ParseReferral(string whoisOutput)
    {
        // Look for "refer:" or "whois:" lines
        using var reader = new StringReader(whoisOutput);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.StartsWith("refer:", StringComparison.OrdinalIgnoreCase) || 
                line.StartsWith("whois:", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':');
                if (parts.Length > 1)
                {
                    return parts[1].Trim();
                }
            }
        }
        return null;
    }
}