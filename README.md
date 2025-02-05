# NetCutKiller

A cross-platform Python tool designed to protect against ARP spoofing attacks by monitoring and securing network communications.

## Overview

NetCutKiller is a security utility that helps defend against Address Resolution Protocol (ARP) based attacks, including ARP spoofing and man-in-the-middle attacks. It works by:

- Setting up static ARP entries for your gateway
- Continuously monitoring network traffic for suspicious ARP packets
- Automatically reinforcing protection when potential attacks are detected
- Supporting Windows, Linux, and macOS systems

## Prerequisites

- Python 3.6 or higher
- Scapy library
- Administrator/root privileges (required for ARP table modifications)
- Network interface with active connection

### Required Python Packages

```
scapy>=2.4.0
```

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/network-protector.git
cd network-protector
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage requires only your gateway IP address:

```bash
python netcutkiller.py 192.168.1.1
```

### Advanced Options

```bash
python netcutkiller.py <gateway_ip> [--gateway-mac MAC_ADDRESS] [--interface INTERFACE_NAME]
```

Parameters:
- `gateway_ip`: Your network gateway's IP address (required)
- `--gateway-mac`: Gateway's MAC address (optional, will be auto-detected)
- `--interface`: Specific network interface to monitor (optional)

## Features

- **Cross-Platform Support**: Works on Windows, Linux, and macOS
- **Automatic Gateway Detection**: Automatically determines gateway MAC address
- **Real-time Monitoring**: Continuously monitors for ARP spoofing attempts
- **Automatic Protection**: Reinstates protection when attacks are detected
- **Detailed Logging**: Provides comprehensive logging of security events

## How It Works

1. The tool first establishes your gateway's legitimate MAC address
2. Sets up static ARP entries in your system's ARP table
3. Monitors network traffic for suspicious ARP packets
4. When potential attacks are detected:
   - Logs the incident with details
   - Reinforces system protection
   - Alerts the user

## Security Considerations

- Requires root/administrator privileges
- Modifies system ARP tables
- Should be used with caution in production environments
- Not a replacement for comprehensive network security measures

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure you're running with administrator/root privileges

2. **Interface Not Found**
   - Verify the network interface name
   - Try running without the --interface parameter

3. **Gateway MAC Detection Failure**
   - Manually specify the gateway MAC address using --gateway-mac
   - Verify network connectivity

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided as-is for educational and defensive purposes only. Users are responsible for ensuring compliance with local laws and network policies before deployment.
