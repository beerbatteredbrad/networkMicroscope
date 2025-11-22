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
*   **JA4S Fingerprinting:** Calculate the JA4 server fingerprint to identify server types and potential threats.

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

**Full Suite:**
```powershell
dotnet run --project NetworkMicroscope.CLI -- --target google.com --test all
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
