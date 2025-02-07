# Network Security Tools

## Tools Overview

### NetCutKiller
A defensive tool designed to protect against ARP spoofing attacks by monitoring and securing network communications.

Key Features:
- Automatic gateway detection on all platforms
- Sets up static ARP entries for your gateway
- Continuously monitors network traffic for suspicious ARP packets
- Automatically reinforces protection when potential attacks are detected
- Provides detailed logging of security events

### NetCut
A network testing tool that simulates ARP spoofing attacks to help assess network security.

Key Features:
- Discovers active devices on the local network
- Generates and sends fake ARP responses
- Supports custom MAC address spoofing
- Automatic gateway detection and targeting
- Supports targeting specific IP addresses
- Supports both broad and focused testing scenarios

## Prerequisites

- Python 3.6 or higher
- Scapy library
- Administrator/root privileges (required for ARP table modifications)
- Network interface with active connection

### Required Python Packages

```
scapy>=2.4.0
```

### Platform-Specific Requirements
- **Windows**: Install [Npcap](https://npcap.com/#download) (recommended) or WinPcap for packet capture support.
- **Linux**: Install `libpcap-dev` (Debian-based) or `libpcap-devel` (Red Hat-based) for packet capture support.
- **macOS**: No additional installation required (libpcap is pre-installed).

## Installation

1. Clone this repository:
```bash
git clone https://github.com/tboy1337/netcut.git
cd netcut
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### NetCutKiller (Defense)

Basic usage with automatic gateway detection:

```bash
python netcutkiller.py
```

Advanced Options:
```bash
python netcutkiller.py [--gateway-ip GATEWAY_IP] [--gateway-mac MAC_ADDRESS] [--interface INTERFACE_NAME]
```

Parameters:
- `--gateway-ip`: Your network gateway's IP address (optional, will be auto-detected)
- `--gateway-mac`: Gateway's MAC address (optional, will be auto-detected)
- `--interface`: Specific network interface to monitor (optional)

### NetCut (Offense)

Basic usage with automatic gateway detection (affects all LAN devices):

```bash
python netcut.py
```

Target a specific IP address:
```bash
python netcut.py --target-ip 192.168.1.100
```

Advanced Options:
```bash
python netcut.py [--fake-mac MAC_ADDRESS] [--gateway-ip GATEWAY_IP] [--interface INTERFACE_NAME] [--target-ip TARGET_IP]
```

Parameters:
- `--fake-mac`: Custom MAC address for spoofing (optional, random MAC will be generated)
- `--gateway-ip`: Gateway IP address (optional, will be auto-detected)
- `--interface`: Specific network interface to use (optional)
- `--target-ip`: Specific IP address to target (optional, will target all LAN IPs if not provided)

## Features

### Cross-Platform Support
- Works on Windows, Linux, and macOS
- Automatic gateway detection on all platforms
- Interface auto-detection with manual override option

### Security Features (NetCutKiller)
- Automatic gateway IP and MAC detection
- Real-time ARP packet monitoring
- Automatic attack detection and response
- Detailed security event logging
- Static ARP entry management

### Testing Features (NetCut)
- LAN device discovery
- Single IP targeting capability
- Customizable MAC address spoofing
- Continuous ARP packet transmission
- Detailed operation logging
- Selective targeting for focused testing

## Security Considerations

- Both tools require root/administrator privileges
- Modify system ARP tables and network configurations
- Should be used with caution in production environments
- NetCut should only be used in controlled testing environments
- Neither tool is a replacement for comprehensive network security
- When using single IP targeting, ensure proper authorization

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure you're running with administrator/root privileges
   - Check user permissions for network interface access

2. **Interface Not Found**
   - Verify the network interface name
   - Try running without the --interface parameter
   - Check if the interface is up and active

3. **Gateway Detection Failure**
   - If auto-detection fails, manually specify the gateway IP using --gateway-ip
   - Verify network connectivity
   - Check if the gateway is responding to ARP requests
   - Ensure your system's network configuration is correct

4. **MAC Address Detection Issues**
   - If gateway MAC detection fails, specify it manually using --gateway-mac
   - Verify that the gateway IP is correct
   - Check for firewall rules that might block ARP requests

5. **Target IP Issues**
   - Ensure the target IP is valid and within your network range
   - Verify the target device is active and responding to ARP
   - Check network connectivity to the target IP
   - Ensure proper network permissions and access rights

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

These tools are provided as-is for educational and testing purposes only. Users are responsible for:
- Ensuring compliance with local laws and regulations
- Following network policies and obtaining necessary permissions
- Using the tools responsibly and ethically
- Understanding the potential risks and implications of network testing
- Obtaining proper authorization before targeting specific devices

The authors are not responsible for any misuse or damage caused by these tools.
