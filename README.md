# 🔬 Network Microscope

> **A Swiss-Army Knife for Network Diagnostics & Deep Analysis**

![.NET](https://img.shields.io/badge/.NET-10.0-purple)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**Network Microscope** is a powerful, modular network diagnostic tool built on **.NET 10**. It goes beyond simple `ping` and `tracert` to provide deep insights into network connectivity, protocol support, security posture, and reliability.

Designed for network engineers, developers, and sysadmins who need to see *exactly* what's happening on the wire.

---

## ✨ Features

### 🔌 Connectivity & Path
*   **Dual-Stack Support:** Automatically tests both IPv4 and IPv6 paths.
*   **TCP/UDP Reachability:** Verify port openness and protocol responsiveness.
*   **Advanced Traceroute:** Visualize the path and hop latencies.
*   **Path MTU Discovery:** Detect fragmentation issues.
*   **Port Scanning:** Quickly check the top 20 common ports.

### 🛡️ Protocol & Security
*   **HTTP/3 (QUIC):** Verify if the target supports the latest web protocols.
*   **TLS Analysis:** Inspect handshake details, cipher suites, and certificate chains.
*   **JA4+ Fingerprinting:** 
    *   **JA4S (TLS):** Server-side TLS fingerprinting (supports ALPN).
    *   **JA4 (QUIC):** HTTP/3 fingerprinting over UDP.

### 🧠 Network Intelligence
*   **ASN & GeoIP:** Identify the ISP, location, and Autonomous System of the target.
*   **WHOIS:** Retrieve domain registration details.

### 🚀 Performance & Reliability
*   **Latency Testing:** Precision ping and TCP ping measurements.
*   **Bandwidth Estimation:** Download speed tests against HTTP/HTTPS endpoints.
*   **TCP Spray (Reliability):** 🆕 Send a burst of user-mode TCP probes to measure **packet loss**, **jitter**, and **latency** without requiring raw sockets or admin privileges.

---

## 📦 Installation

### Prerequisites
*   [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet) (Preview/RC)
*   Windows OS (for full feature support)

### Build
Clone the repository and build the solution:

```powershell
git clone https://github.com/beerbatteredbrad/networkMicroscope.git
cd networkMicroscope
dotnet build
```

---

## 🎮 Usage

You can use **Network Microscope** in two ways: via the interactive PowerShell menu or directly via the CLI.

### 1. Interactive Mode (Recommended)
The easiest way to explore. Run the PowerShell script:

```powershell
.\Microscope.ps1
```

This launches a menu where you can select targets and tests dynamically.

### 2. CLI Mode (Automation)
Run specific tests directly from your terminal.

**Basic Connectivity Test:**
```powershell
dotnet run --project NetworkMicroscope.CLI -- --target google.com --test connectivity
```

**TCP Spray (Reliability Test):**
*Check for packet loss with 100 probes (default)*
```powershell
dotnet run --project NetworkMicroscope.CLI -- --target google.com --test tcpspray
```

*Customize probe count (e.g., 500 probes)*
```powershell
dotnet run --project NetworkMicroscope.CLI -- --target google.com --test tcpspray --probes 500
```

**JA4 Fingerprinting (TLS & QUIC):**
*Generate JA4S and JA4 (QUIC) fingerprints*
```powershell
dotnet run --project NetworkMicroscope.CLI -- --target google.com --test ja4
```

**Full Suite:**
```powershell
dotnet run --project NetworkMicroscope.CLI -- --target google.com --test all
```

---

## 📸 Example Output

### 1. Connectivity Test
*Verifies DNS, IPv4/IPv6 reachability, and basic HTTP response.*

```text
PS C:\NetworkMicroscope> dotnet run --project NetworkMicroscope.CLI -- --target google.com --test connectivity

Network Microscope CLI
Target: google.com, Port: 443, Test: connectivity
--------------------------------------------------

==================================================
 Running Connectivity Tests...
==================================================
[PASS] TCP Connect (Default): Successfully connected to google.com:443 via TCP. (12ms)
[PASS] TCP Connect (IPv4: 142.250.190.46): Successfully connected to 142.250.190.46:443 via TCP. (12ms)
[PASS] TCP Connect (IPv6: 2607:f8b0:4009:804::200e): Successfully connected to 2607:f8b0:4009:804::200e:443 via TCP. (15ms)
[PASS] UDP Reachability: UDP Packet sent to google.com:443. (1ms)
```

### 2. TCP Spray (Reliability)
*Sends a burst of concurrent TCP probes to measure latency, jitter, and packet loss.*

```text
PS C:\NetworkMicroscope> dotnet run --project NetworkMicroscope.CLI -- --target google.com --test tcpspray --probes 100

Network Microscope CLI
Target: google.com, Port: 443, Test: tcpspray
--------------------------------------------------

==================================================
 Running TCP Spray (Reliability Test) with 100 probes...
==================================================
[PASS] TCP Spray: TCP Spray Completed.
    Sent: 100, Received: 100
    Loss: 0.0%
    Latency (ms): Min=11, Max=45, Avg=14
    Jitter: 3ms
```

### 3. JA4 Fingerprinting (TLS & QUIC)
*Generates JA4S (Server) and JA4 (QUIC) fingerprints for security analysis.*

```text
PS C:\NetworkMicroscope> dotnet run --project NetworkMicroscope.CLI -- --target facebook.com --test ja4

Network Microscope CLI
Target: facebook.com, Port: 443, Test: ja4
--------------------------------------------------

==================================================
 Running JA4 Fingerprinting...
==================================================
[PASS] JA4S (Server - Default): JA4S Calculated.
    Fingerprint: t1300_1301_c35a6cc4faa0
    Details: Ver: 13, Cipher: 1301, Exts: 2, Negotiated ALPN: None
[PASS] JA4S (IPv4: 157.240.3.35): JA4S Calculated.
    Fingerprint: t1300_1301_c35a6cc4faa0
[PASS] JA4 (QUIC): JA4 (QUIC) Calculated.
    Fingerprint: q13h3_1301_000000000000
    Details: Ver: 13, Cipher: 1301, ALPN: h3, Exts: (Hidden)
```

---

## 🏗️ Architecture

*   **NetworkMicroscope.Core:** The brain. A reusable .NET 10 class library containing all diagnostic logic.
*   **NetworkMicroscope.CLI:** The muscle. A console application wrapper for executing tests.
*   **Microscope.ps1:** The face. A user-friendly PowerShell orchestrator.

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## 📝 License

[MIT](https://choosealicense.com/licenses/mit/)
