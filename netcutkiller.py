import argparse
import platform
import subprocess
import sys
import time
from typing import List, Tuple
import logging
from scapy.all import (
    sniff, 
    Ether, 
    ARP, 
    sendp, 
    conf, 
    get_if_list,
    srp,
    get_working_if,
    get_if_addr
)

class NetworkProtector:
    def __init__(self, gateway_ip: str = None, gateway_mac: str = None, interface: str = None):
        self.interface = interface or get_working_if()
        self.gateway_ip = gateway_ip or self._get_default_gateway()
        self.gateway_mac = gateway_mac
        self.os_type = platform.system().lower()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _get_default_gateway(self) -> str:
        """Determine the default gateway IP address."""
        try:
            if self.os_type == "windows":
                result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if "Default Gateway" in line:
                        gateway = line.split(":")[1].strip()
                        if gateway and gateway != "":
                            return gateway
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

    def protect_system(self) -> None:
        """Set up ARP protection based on operating system."""
        if not self.gateway_ip:
            self.logger.error("Gateway IP could not be determined")
            sys.exit(1)
            
        if not self.gateway_mac:
            self.gateway_mac = self.get_gateway_mac()
            
        if not self.gateway_mac:
            self.logger.error("Could not determine gateway MAC address")
            sys.exit(1)

        try:
            if self.os_type == "windows":
                self._protect_windows()
            elif self.os_type == "linux":
                self._protect_linux()
            elif self.os_type == "darwin":
                self._protect_macos()
            else:
                self.logger.error(f"Unsupported operating system: {self.os_type}")
                sys.exit(1)
                
            self.logger.info(f"ARP protection enabled for {self.os_type}")
            self.logger.info(f"Gateway IP: {self.gateway_ip}")
            self.logger.info(f"Gateway MAC: {self.gateway_mac}")
        except Exception as e:
            self.logger.error(f"Failed to set up protection: {str(e)}")
            sys.exit(1)

    def _protect_windows(self) -> None:
        """Set up ARP protection on Windows."""
        try:
            subprocess.run(
                ["netsh", "interface", "ipv4", "add", "neighbors", 
                 self.interface, self.gateway_ip, self.gateway_mac],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to set Windows ARP entry: {e.stderr.decode()}")
            raise

    def _protect_linux(self) -> None:
        """Set up ARP protection on Linux."""
        try:
            subprocess.run(
                ["sudo", "arp", "-s", self.gateway_ip, self.gateway_mac],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to set Linux ARP entry: {e.stderr.decode()}")
            raise

    def _protect_macos(self) -> None:
        """Set up ARP protection on macOS."""
        try:
            subprocess.run(
                ["sudo", "arp", "-S", self.gateway_ip, self.gateway_mac],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to set macOS ARP entry: {e.stderr.decode()}")
            raise

    def get_gateway_mac(self) -> str:
        """Determine gateway MAC address using ARP."""
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.gateway_ip),
                timeout=2,
                verbose=False,
                iface=self.interface
            )
            if ans:
                return ans[0][1].hwsrc
            return None
        except Exception as e:
            self.logger.error(f"Failed to get gateway MAC: {str(e)}")
            return None

    def monitor_network(self) -> None:
        """Monitor network for potential ARP-based attacks."""
        self.logger.info("Starting network monitoring...")
        try:
            sniff(
                filter="arp",
                prn=self._analyze_packet,
                store=0,
                iface=self.interface
            )
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Monitoring error: {str(e)}")

    def _analyze_packet(self, pkt) -> None:
        """Analyze captured ARP packets for potential attacks."""
        if ARP in pkt and pkt[ARP].op == 2:  # is-at (ARP response)
            if pkt[ARP].psrc == self.gateway_ip and pkt[ARP].hwsrc != self.gateway_mac:
                self.logger.warning(
                    f"Potential ARP spoofing detected!\n"
                    f"Claimed gateway IP: {pkt[ARP].psrc}\n"
                    f"Incorrect MAC: {pkt[ARP].hwsrc}\n"
                    f"Real gateway MAC: {self.gateway_mac}"
                )
                self.protect_system()  # Reinforce protection

def main():
    parser = argparse.ArgumentParser(
        description="Cross-platform network protection against ARP-based attacks"
    )
    parser.add_argument(
        "--gateway-ip",
        help="Gateway IP address (optional, will be auto-detected if not provided)",
        default=None
    )
    parser.add_argument(
        "--gateway-mac",
        help="Gateway MAC address (optional, will be auto-detected if not provided)",
        default=None
    )
    parser.add_argument(
        "--interface",
        help="Network interface to use (optional)",
        default=None
    )
    
    args = parser.parse_args()
    
    protector = NetworkProtector(
        gateway_ip=args.gateway_ip,
        gateway_mac=args.gateway_mac,
        interface=args.interface
    )
    
    protector.protect_system()
    protector.monitor_network()

if __name__ == "__main__":
    main()
