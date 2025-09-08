# Port-Scanner-
This Python port scanner is a comprehensive network reconnaissance tool designed for security professionals, network administrators, and cybersecurity students. It combines speed, functionality, and detailed logging to provide thorough port scanning capabilities. 

# Key Features:
Core Functionality:

Multi-threaded scanning using ThreadPoolExecutor for optimal performance
Service detection and banner grabbing
Support for single hosts or IP ranges (CIDR notation)
Configurable timeout and thread count

# Logging System:

Dual logging to both file and console
Timestamped log files with detailed scan information
Structured logging format with different levels

# Service Detection:

Common port-to-service mappings
Banner grabbing for HTTP services
Service name resolution using socket.getservbyport()

# Advanced Options:

Flexible port specification (ranges or specific ports)
IP range scanning with CIDR notation
Adjustable thread count and timeout settings
Comprehensive error handling

Usage Examples:
bash# Basic scan
python port_scanner.py -t 192.168.1.1

# Scan specific port range with more threads
python port_scanner.py -t example.com -p 1-1000 --threads 200

# Scan network range
python port_scanner.py -t 192.168.1.0/24 -p 80,443,22,21

# Full port scan with custom timeout
python port_scanner.py -t 10.0.0.1 -p 1-65535 --timeout 2
Technical Highlights:

Threading: Uses ThreadPoolExecutor for efficient concurrent scanning
Logging: Creates timestamped log files and provides real-time console output
Service Detection: Attempts to identify services running on open ports
Banner Grabbing: Retrieves service banners where possible
Error Handling: Robust error handling for network issues and invalid inputs
