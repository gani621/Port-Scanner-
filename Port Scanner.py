#!/usr/bin/env python3
"""
Advanced Port Scanner with Multi-threading and Service Detection
Features:
- Multi-threaded scanning for improved speed
- Service detection and banner grabbing
- Comprehensive logging
- Configurable timeout and thread count
- Support for single host or IP range scanning
"""

import socket
import threading
import argparse
import logging
import time
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1000, threads=100, timeout=1):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()
        
        # Setup logging
        self.setup_logging()
        
        # Common service mappings
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB'
        }
    
    def setup_logging(self):
        """Configure logging to both file and console"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"port_scan_{self.target.replace('.', '_')}_{timestamp}.log"
        
        # Create logger
        self.logger = logging.getLogger('PortScanner')
        self.logger.setLevel(logging.INFO)
        
        # Create file handler
        file_handler = logging.FileHandler(log_filename)
        file_handler.setLevel(logging.INFO)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        self.logger.info(f"Port scan started for {self.target}")
        self.logger.info(f"Scanning ports {self.start_port}-{self.end_port}")
        self.logger.info(f"Using {self.threads} threads with {self.timeout}s timeout")
    
    def scan_port(self, host, port):
        """Scan a single port on the target host"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((host, port))
            
            if result == 0:
                service = self.detect_service(sock, port)
                
                with self.lock:
                    port_info = {
                        'port': port,
                        'service': service,
                        'banner': self.grab_banner(host, port)
                    }
                    self.open_ports.append(port_info)
                    
                    service_name = self.common_ports.get(port, 'Unknown')
                    self.logger.info(f"OPEN: {host}:{port} - {service_name} - {service}")
                
            sock.close()
            
        except socket.gaierror:
            self.logger.error(f"Hostname {host} could not be resolved")
        except Exception as e:
            pass  # Silently ignore connection errors for closed ports
    
    def detect_service(self, sock, port):
        """Detect service running on the port"""
        try:
            # Get service name from port number
            service_name = socket.getservbyport(port)
            return service_name
        except:
            return self.common_ports.get(port, 'Unknown')
    
    def grab_banner(self, host, port):
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', 'ignore').strip()
            sock.close()
            return banner[:100] if banner else "No banner"
            
        except:
            return "No banner"
    
    def scan_host(self, host):
        """Scan all ports on a single host"""
        self.logger.info(f"Scanning host: {host}")
        
        # Create thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all port scan tasks
            futures = []
            for port in range(self.start_port, self.end_port + 1):
                future = executor.submit(self.scan_port, host, port)
                futures.append(future)
            
            # Wait for all tasks to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Error scanning port: {e}")
    
    def scan_range(self, ip_range):
        """Scan a range of IP addresses"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            for ip in network:
                self.target = str(ip)
                self.open_ports = []  # Reset for each host
                self.scan_host(str(ip))
                self.display_results()
                
        except ValueError as e:
            self.logger.error(f"Invalid IP range: {e}")
    
    def display_results(self):
        """Display scan results"""
        if self.open_ports:
            self.logger.info(f"\n=== SCAN RESULTS FOR {self.target} ===")
            self.logger.info(f"Found {len(self.open_ports)} open ports:")
            
            for port_info in sorted(self.open_ports, key=lambda x: x['port']):
                port = port_info['port']
                service = port_info['service']
                banner = port_info['banner']
                
                self.logger.info(f"Port {port}: {service}")
                if banner and banner != "No banner":
                    self.logger.info(f"  Banner: {banner}")
        else:
            self.logger.info(f"No open ports found on {self.target}")
    
    def run(self):
        """Run the port scanner"""
        start_time = time.time()
        
        # Check if target is an IP range
        if '/' in self.target:
            self.scan_range(self.target)
        else:
            self.scan_host(self.target)
            self.display_results()
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        self.logger.info(f"\nScan completed in {scan_duration:.2f} seconds")
        self.logger.info(f"Results saved to log file")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Multi-threaded Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t example.com -p 1-1000 --threads 200
  python port_scanner.py -t 192.168.1.0/24 -p 80,443,22,21
  python port_scanner.py -t 10.0.0.1 -p 1-65535 --timeout 2
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                        help='Target host or IP range (e.g., 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', default='1-1000',
                        help='Port range (e.g., 1-1000) or specific ports (e.g., 80,443,22)')
    parser.add_argument('--threads', type=int, default=100,
                        help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1,
                        help='Connection timeout in seconds (default: 1)')
    
    args = parser.parse_args()
    
    # Parse port range
    try:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        elif ',' in args.ports:
            # Handle specific ports
            ports = list(map(int, args.ports.split(',')))
            start_port, end_port = min(ports), max(ports)
        else:
            start_port = end_port = int(args.ports)
    except ValueError:
        print("Error: Invalid port specification")
        sys.exit(1)
    
    # Validate arguments
    if start_port < 1 or end_port > 65535:
        print("Error: Port numbers must be between 1 and 65535")
        sys.exit(1)
    
    if args.threads < 1 or args.threads > 1000:
        print("Error: Thread count must be between 1 and 1000")
        sys.exit(1)
    
    # Create and run scanner
    try:
        scanner = PortScanner(
            target=args.target,
            start_port=start_port,
            end_port=end_port,
            threads=args.threads,
            timeout=args.timeout
        )
        scanner.run()
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()