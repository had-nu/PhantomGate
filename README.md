# PhantomGate

[![Go Version](https://img.shields.io/github/go-mod/go-version/phantomgate/phantomgate?filename=go.mod)](https://github.com/phantomgate/phantomgate)
[![License](https://img.shields.io/github/license/phantomgate/phantomgate)](LICENSE)
[![Release](https://img.shields.io/github/v/release/phantomgate/phantomgate)](https://github.com/phantomgate/phantomgate/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/phantomgate/phantomgate)](https://goreportcard.com/report/github.com/phantomgate/phantomgate)
[![Build Status](https://img.shields.io/github/actions/workflow/status/phantomgate/phantomgate/build.yml?branch=main)](https://github.com/phantomgate/phantomgate/actions/workflows/build.yml)
[![CodeQL](https://github.com/phantomgate/phantomgate/actions/workflows/codeql.yml/badge.svg)](https://github.com/phantomgate/phantomgate/actions/workflows/codeql.yml)
[![Contributors](https://img.shields.io/github/contributors/phantomgate/phantomgate)](https://github.com/phantomgate/phantomgate/graphs/contributors)
[![Last Commit](https://img.shields.io/github/last-commit/phantomgate/phantomgate)](https://github.com/phantomgate/phantomgate/commits/main)

<p align="center">
  <img src="assets/logo.png" alt="PhantomGate Logo" width="300" />
</p>

<p align="center">
  <b>Advanced Traffic Anonymization Tool with Tor and Private Proxy Support</b>
</p>

PhantomGate is a simple Go-based anonymization tool that routes your internet traffic through multiple layers of protection including Tor and private proxies to ensure maximum privacy and security online.

## Features

- **Multiple Anonymization Methods**
  - Tor network routing
  - Private proxy lists support (SOCKS5, HTTP, HTTPS)
  - Multi-layer anonymization (proxies + Tor)

- **Advanced Proxy Management**
  - JSON-based proxy configuration
  - Proxy authentication support
  - Automatic proxy rotation

- **Security Verification**
  - DNS leak testing
  - WebRTC leak detection
  - Browser fingerprinting protection

- **Enhanced Privacy**
  - Stealth mode for additional protection layers
  - Full iptables configuration on Linux
  - Automatic IP address rotation

- **User Friendly**
  - Clear command-line interface
  - Detailed activity logging
  - Cross-platform support

## Architecture

PhantomGate provides multiple layers of anonymity to protect your online identity:

```
┌───────────────┐     ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│               │     │               │     │               │     │               │
│  Your Device  │────▶│ Private Proxy │────▶│  Tor Network  │────▶│  Destination  │
│               │     │               │     │               │     │               │
└───────────────┘     └───────────────┘     └───────────────┘     └───────────────┘
```

## Installation

### Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/phantomgate/phantomgate/releases) page.

### Building from Source

```bash
# Clone the repository
git clone https://github.com/had-nu/phantomgate.git
cd phantomgate

# Build the project
go build -o phantomgate main.go
```

### Requirements

- Go 1.18+ (for building from source)
- Root/Administrator privileges
- Tor (optional, will be installed automatically if missing)

## Usage

PhantomGate must be run with administrator/root privileges:

```bash
sudo ./phantomgate --start
```

### Command-line Options

```
--start         Start PhantomGate
--stop          Stop PhantomGate and restore network settings
--new-ip        Get a new IP address
--ip            Show current public IP address
--auto          Automatically change IP at regular intervals
--time N        Set interval for automatic IP changes (seconds)
--proxy         Use private proxy list instead of Tor
--add-proxy     Add a new proxy to the list
--no-tor        Don't use Tor (use only with proxies)
--check-leaks   Check for privacy leaks
--stealth       Enable stealth mode (extra privacy features)
--debug         Enable debug logging
--version       Show version information
```

## Example Workflows

### Basic Privacy with Tor

```bash
sudo ./phantomgate --start
```

### Using Private Proxies Only

```bash
sudo ./phantomgate --proxy --no-tor --start
```

### Maximum Anonymization (Proxies + Tor)

```bash
sudo ./phantomgate --proxy --tor --stealth --start
```

### Automatic IP Rotation (Every 5 minutes)

```bash
sudo ./phantomgate --auto --time 300 --start
```

## Proxy Configuration

PhantomGate uses a JSON file to manage your private proxies. The file is stored at `~/.phantomgate_proxies.json` with the following structure:

```json
[
  {
    "type": "socks5",
    "address": "proxy1.example.com:1080",
    "username": "user",
    "password": "pass"
  },
  {
    "type": "http",
    "address": "proxy2.example.com:8080",
    "username": "",
    "password": ""
  }
]
```

Add new proxies with:

```bash
sudo ./phantomgate --add-proxy
```

## Security Verification

Run security checks to ensure there are no leaks:

```bash
sudo ./phantomgate --check-leaks
```

## Comparison with Similar Tools

| Feature | PhantomGate | ZeroTrace | Tor Browser | VPN |
|---------|-------------|-----------|-------------|-----|
| Tor Network | ✅ | ✅ | ✅ | ❌ |
| Custom Proxies | ✅ | ❌ | ❌ | ❌ |
| Multi-layer Routing | ✅ | ❌ | ❌ | ❌ |
| Leak Testing | ✅ | ❌ | ✅ | ❌ |
| Private DNS | ✅ | ✅ | ✅ | Varies |
| IP Rotation | ✅ | ✅ | ✅ | ❌ |
| Open Source | ✅ | ✅ | ✅ | Varies |
| Cross-platform | ✅ | ❌ | ✅ | ✅ |

## Screenshots

<div align="center">
  <img src="assets/screenshot1.png" alt="Starting PhantomGate" width="600" />
  <p><i>Starting PhantomGate with Tor + Private Proxy</i></p>
  <br>
  <img src="assets/screenshot2.png" alt="IP Rotation" width="600" />
  <p><i>Automatic IP rotation in action</i></p>
</div>

## Technical Details

### Network Stack Modification

PhantomGate modifies the system's network stack to route traffic through the anonymization layers:

```
┌─────────────────────────────────────────────────────────────┐
│ User Applications                                           │
└───────────────┬─────────────────────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────────────────┐
│ PhantomGate Routing Layer                                   │
│                                                             │
│  ┌───────────────┐    ┌───────────────┐    ┌──────────────┐ │
│  │ IP Tables     │───▶│ Proxy Manager │───▶│ Tor Routing  │ │
│  └───────────────┘    └───────────────┘    └──────────────┘ │
└───────────────┬─────────────────────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────────────────┐
│ Network Interface                                           │
└─────────────────────────────────────────────────────────────┘
```

### Privacy Testing Procedures

PhantomGate conducts the following checks to ensure privacy:

1. **DNS Leak Test**: Ensures that DNS requests are properly routed through Tor
2. **WebRTC Leak Test**: Prevents browsers from revealing your real IP address
3. **Fingerprinting Test**: Checks if your browser is leaking identifiable information

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

PhantomGate is designed for legitimate privacy and security purposes. Please use this tool responsibly and in compliance with all applicable laws. TI am not responsible for any misuse of this software.

## Acknowledgments

- The Tor Project for providing the anonymous network
- Go community for the excellent networking libraries
- Contributors to the project