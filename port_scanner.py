#!/usr/bin/env python3
import socket
import sys
import re
import argparse
from concurrent.futures import ThreadPoolExecutor
import time

def is_valid_ip(ip):
    """Validate if the given string is a valid IPv4 address."""
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    
    # Check each octet is between 0 and 255
    for octet in match.groups():
        if int(octet) > 255:
            return False
    return True

def scan_port(ip, port, timeout=1):
    """Scan a specific port on the given IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            sock.close()
            return port, True, service
        sock.close()
        return port, False, None
    except socket.error:
        return port, False, None

def print_progress(current, total):
    """Print a simple progress bar."""
    bar_length = 30
    percent = current / total
    arrow = '=' * int(bar_length * percent)
    spaces = ' ' * (bar_length - len(arrow))
    sys.stdout.write(f"\r[{arrow}{spaces}] {int(percent * 100)}% ({current}/{total} ports)")
    sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description="Basic Port Scanner")
    parser.add_argument("ip", help="IP address to scan")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-1024)", default="1-1024")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads to use", default=50)
    parser.add_argument("--timeout", type=float, help="Socket timeout in seconds", default=1.0)
    args = parser.parse_args()
    
    # Validate IP address
    if not is_valid_ip(args.ip):
        print(f"Error: '{args.ip}' is not a valid IPv4 address.")
        sys.exit(1)
    
    # Parse port range
    try:
        if "-" in args.ports:
            start_port, end_port = map(int, args.ports.split("-"))
        else:
            start_port = end_port = int(args.ports)
        
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError("Port numbers must be between 1 and 65535")
        if start_port > end_port:
            start_port, end_port = end_port, start_port
    except ValueError as e:
        print(f"Error: Invalid port range '{args.ports}'. {e}")
        sys.exit(1)
    
    # Begin scanning
    ports_to_scan = list(range(start_port, end_port + 1))
    total_ports = len(ports_to_scan)
    
    print(f"\nStarting scan on host {args.ip} for ports {start_port}-{end_port}")
    print(f"Using {args.threads} threads with {args.timeout}s timeout\n")
    
    start_time = time.time()
    open_ports = []
    
    # Use ThreadPoolExecutor to scan ports concurrently
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for port in ports_to_scan:
            futures.append(executor.submit(scan_port, args.ip, port, args.timeout))
        
        # Process results as they complete
        for i, future in enumerate(futures, 1):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))
            print_progress(i, total_ports)
    
    # Calculate scan duration
    duration = time.time() - start_time
    
    # Display results
    print("\n\nScan completed in {:.2f} seconds".format(duration))
    
    if open_ports:
        print("\n{:<10} {:<10}".format("PORT", "SERVICE"))
        print("-" * 25)
        for port, service in sorted(open_ports):
            print("{:<10} {:<10}".format(port, service))
        print(f"\nFound {len(open_ports)} open port(s) out of {total_ports} scanned.")
    else:
        print("\nNo open ports found in the specified range.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan terminated by user.")
        sys.exit(0)
