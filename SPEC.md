# Network Microscope Specification

## Overview
A "swiss-army knife" network diagnostic tool designed to perform deep analysis on a target FQDN or IP address. The core logic will be implemented in .NET 10, orchestrated by a user-interactive PowerShell script.

## Technology Stack
- **Core Logic:** .NET 10 Class Library (`.dll`) for reusability.
- **CLI Wrapper:** .NET 10 Console Application (`.exe`) referencing the library.
- **Interface:** PowerShell Script (User-Interactive & Parameterized).
- **Operating System:** Windows

## Inputs
- Target: FQDN (Fully Qualified Domain Name) or IP Address
- Port (optional/contextual)
- HTTP/HTTPS Endpoint (for bandwidth tests)
- Probes (optional, default 100) - Number of TCP connection attempts for spray test
- Output Path (optional for JSON report)

## Proposed Features
1.  **Connectivity & Path Analysis:**
    - TCP Connect (Dual Stack IPv4/IPv6 support, 2s timeout for IP-specific tests)
    - UDP Reachability
    - Port Scanning (Top 20 Common ports)
    - Traceroute (Path visualization & hop latency)
    - Path MTU Discovery (Fragmentation check)
2.  **Protocol Support:**
    - HTTP/3 (QUIC) - Enforced check
    - TLS Analysis (Fingerprinting, Certificate Validation, Dual Stack support)
    - JA4S Fingerprinting (Server-side JA4 calculation, Dual Stack support)
    - JA4 (QUIC) Fingerprinting (HTTP/3 support check with fingerprint generation)
3.  **Network Intelligence & DNS:**
    - ASN Information (via public APIs)
    - GeoIP Data
    - Whois Lookup (Domain registration details)
4.  **Performance Metrics:**
    - Latency (Ping/TCP Ping)
    - Bandwidth Estimation (Download test against user-provided HTTP/HTTPS endpoint).
    - TCP Spray (Reliability Test): Sends a burst of TCP connection attempts (default 100) to measure packet loss, latency, and jitter without using ICMP.
5.  **Reporting:**
    - Console Output.
    - Optional JSON file export (Future).

## Architecture
- **NetworkMicroscope.Core (Class Library):** Contains all networking logic and test implementations.
- **NetworkMicroscope.CLI (Console App):** A thin wrapper around the Core library to allow execution as an `.exe`.
- **Microscope.ps1 (PowerShell Script):** 
    - Supports command-line parameters for automation.
    - Supports an interactive text-based menu mode if launched without parameters (or with `-Interactive`).
    - Can invoke the `.exe` or load the `.dll` directly (primary method: invoke `.exe` for simplicity, or load `.dll` for advanced integration).

## Implementation Details
- **ConnectivityTester:** Handles TCP/UDP checks.
- **ProtocolTester:** Handles HTTP/3 and TLS analysis.
- **NetworkIntelligenceTester:** Handles ASN/GeoIP lookups via `ipinfo.io`.
- **WhoisProvider:** Handles Legacy WHOIS queries via TCP port 43 (RFC 3912).
- **PerformanceTester:** Handles Latency (Ping) and Bandwidth (Download).
- **TcpSprayTester:** Handles TCP Spray reliability testing (Packet Loss, Jitter) via rapid user-mode connection attempts.
- **AdvancedNetworkTester:** Handles Traceroute, Path MTU Discovery, and Port Scanning.
- **Ja4Tester:** 
    - Handles JA4S (Server) fingerprint calculation by intercepting the TLS handshake using a custom `TlsSnoopingStream` wrapper around `SslStream`.
    - Handles JA4 (QUIC) fingerprinting using `System.Net.Quic` to negotiate HTTP/3 and extract cipher/ALPN details.

## Testing Strategy
- **Unit Tests:** `NetworkMicroscope.Tests` covers parsing logic (JA4S for TLS 1.2/1.3, ALPN variations, edge cases) and mocked intelligence providers.
- **Integration Tests:** Validates real network connectivity against standard targets (e.g., google.com) for TCP, TLS, Performance, and JA4S fingerprint format validation.
