<#
.SYNOPSIS
    Network Microscope - A Swiss-army knife for network diagnostics.
.DESCRIPTION
    Orchestrates the .NET 10 NetworkMicroscope tools.
    Can run interactively or via parameters.
.EXAMPLE
    .\Microscope.ps1 -Target "google.com" -Port 443
.EXAMPLE
    .\Microscope.ps1 -Interactive
#>
param(
    [string]$Target,
    [int]$Port,
    [string]$DownloadUrl,
    [switch]$Interactive
)

# Path to the CLI executable (assuming standard build output)
$exePath = Join-Path $PSScriptRoot "NetworkMicroscope.CLI\bin\Debug\net10.0\NetworkMicroscope.CLI.exe"

# Check if the executable exists
if (-not (Test-Path $exePath)) {
    Write-Warning "Executable not found at $exePath."
    Write-Warning "Please build the project first using 'dotnet build'."
    return
}

function Show-Menu {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   NETWORK MICROSCOPE (Interactive)     " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "1. Set Target (Current: $Target)"
    Write-Host "2. Set Download URL (Current: $DownloadUrl)"
    Write-Host "3. Run Connectivity Tests (TCP/UDP)"
    Write-Host "4. Run Protocol Analysis (HTTP/3, TLS)"
    Write-Host "5. Run Network Intelligence (ASN, GeoIP, Whois)"
    Write-Host "6. Run Performance Tests (Latency, Bandwidth)"
    Write-Host "7. Run Advanced Tests (Traceroute, PMTU, Port Scan)"
    Write-Host "8. Run JA4 Fingerprinting"
    Write-Host "9. Run TCP Spray (Reliability)"
    Write-Host "10. Run All Tests"
    Write-Host "Q. Quit"
    Write-Host "========================================" -ForegroundColor Cyan
}

if ($Interactive -or (-not $Target)) {
    # Interactive Mode
    do {
        Show-Menu
        $choice = Read-Host "Select an option"
        switch ($choice) {
            "1" { $Target = Read-Host "Enter Target (FQDN or IP)" }
            "2" { $DownloadUrl = Read-Host "Enter Download URL (for bandwidth test)" }
            "3" { & $exePath --target $Target --test connectivity }
            "4" { & $exePath --target $Target --test protocol }
            "5" { & $exePath --target $Target --test intelligence }
            "6" { & $exePath --target $Target --test performance --download-url $DownloadUrl }
            "7" { & $exePath --target $Target --test advanced }
            "8" { 
                $alpn = Read-Host "Enter explicit ALPN (e.g. h2,http/1.1) [Optional]"
                if ($alpn) {
                    & $exePath --target $Target --test ja4 --alpn $alpn
                } else {
                    & $exePath --target $Target --test ja4
                }
            }
            "9" { 
                $p = Read-Host "Enter number of probes [Default: 100]"
                if (-not $p) { $p = 100 }
                & $exePath --target $Target --test tcpspray --probes $p 
            }
            "10" { & $exePath --target $Target --test all --download-url $DownloadUrl }
            "Q" { return }
            "q" { return }
            Default { Write-Warning "Invalid option" }
        }
        if ($choice -ne "Q" -and $choice -ne "q") {
            Pause
        }
    } while ($true)
}
else {
    # Non-Interactive Mode
    & $exePath --target $Target --port $Port --download-url $DownloadUrl
}