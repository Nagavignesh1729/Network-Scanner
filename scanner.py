import socket
import logging
import warnings
import ipaddress
import argparse
from scapy.all import IP, TCP, sr1, conf
import time
import sys
from cryptography.utils import CryptographyDeprecationWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from tqdm import tqdm

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Set Scapy verbosity for detailed Scapy output (0 to suppress, 1 for some output, 2 for detailed)
conf.verb = 0

logging.basicConfig(
    level=logging.ERROR,  # default set to ERROR
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Default Config
target_ip_range = "192.168.1.1-192.168.1.255"
port_range = "1-1024"
thread_count = 100
output_file = None

service_banners = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    587: "SMTP Secure",
    993: "IMAP Secure",
    995: "POP3 Secure",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    8000: "Common Web Service",
    8080: "HTTP Proxy",
    8443: "HTTPS Alternative",
    9000: "Custom Web Service"
}

# Parsing arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced IP and Port Scanner")
    parser.add_argument("-i", "--ip-range", type=str, default=target_ip_range, help="IP range to scan")
    parser.add_argument("-p", "--port-range", type=str, default=port_range, help="Port range to scan")
    parser.add_argument("-t", "--threads", type=int, default=thread_count, help="Number of threads to use for scanning")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output file location (optional)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed output")
    return parser.parse_args()

# Parse IP range in 'start-end' format and return a list of IP addresses.
def parse_ip_range(ip_range_str):
    try:
        start_ip, end_ip = ip_range_str.split('-')
        start_ip = ipaddress.IPv4Address(start_ip.strip())
        end_ip = ipaddress.IPv4Address(end_ip.strip())
        if start_ip > end_ip:
            raise ValueError("Start IP should be less than or equal to End IP.")
        return [str(ip) for ip in range(int(start_ip), int(end_ip) + 1)]
    except ValueError as e:
        raise ValueError(f"Invalid IP range format: {ip_range_str}. Error: {e}")

# Parse port range and return a list of ports.
def parse_port_range(port_range_str):
    ports = set()
    for part in port_range_str.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start.strip()), int(end.strip()) + 1))
        else:
            ports.add(int(part.strip()))
    return sorted(ports)

# Detecting services using banner grabbing
def detect_service(sock, ip, port):
    service = service_banners.get(port, "Unknown")
    try:
        sock.settimeout(2)
        if port in [80, 8080, 8000, 8443]:
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        elif port == 21:  # FTP
            sock.sendall(b"HELP\r\n")
        elif port == 22:  # SSH
            pass  # SSH servers usually send a version string upon connection
        elif port == 25 or port == 587:  # SMTP
            sock.sendall(b"EHLO example.com\r\n")
        elif port == 110:  # POP3
            sock.sendall(b"STAT\r\n")
        elif port == 143 or port == 993:  # IMAP
            sock.sendall(b". CAPABILITY\r\n")
        elif port == 3306:  # MySQL
            pass  # MySQL servers send a greeting message upon connection
        elif port == 6379:  # Redis
            sock.sendall(b"PING\r\n")
        else:
            sock.sendall(b"\r\n")
        
        response = sock.recv(1024)
        try:
            response_text = response.decode('utf-8', errors='ignore').strip()
        except UnicodeDecodeError:
            response_text = "Non-textual response"
        
        return response_text if response_text else "No response"
    except socket.timeout:
        return "No response (timeout)"
    except Exception as e:
        logging.error(f"Error detecting service on port {port} of {ip}: {e}")
        return f"Error: {e}"

# Simple os finger printing to identify the type of os
def os_fingerprint(ip):
    logging.info(f"Starting OS fingerprinting for {ip}")
    common_ports = [80, 443, 22, 25]
    for port in common_ports:
        syn_packet = IP(dst=ip)/TCP(dport=port, flags='S')
        try:
            response = sr1(syn_packet, timeout=2, verbose=0)
            if response and response.haslayer(TCP):
                ttl = response.ttl
                window_size = response[TCP].window
                
                if ttl <= 64:
                    os_guess = "Linux/Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                else:
                    os_guess = "Unknown"
                
                return f"{os_guess} (TTL: {ttl}, Window Size: {window_size})"
        except Exception as e:
            logging.error(f"Error during OS fingerprinting for {ip} on port {port}: {e}")
            continue
    return "OS detection failed"

# Scan a single ip and port
def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    try:
        sock.connect((ip, port))
        response = detect_service(sock, ip, port)
        os_info = os_fingerprint(ip)
        
        result = {
            "ip": ip,
            "port": port,
            "service": service_banners.get(port, "Unknown"),
            "os": os_info,
            "response": response if response else "No response"
        }

        return result
    
    except socket.timeout:
        return None
    except Exception as e:
        return None
    finally:
        sock.close()

# Run scans and manage progress with tqdm
def run_scans(ip_list, port_list, thread_count, verbose):
    tasks = [(ip, port) for ip in ip_list for port in port_list]
    total_tasks = len(tasks)
    results = []

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        with tqdm(total=total_tasks, desc="Scanning Progress") as progress_bar:
            futures = {executor.submit(scan_port, ip, port): (ip, port) for ip, port in tasks}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    if verbose:
                        logging.info(f"Found open port: {result['ip']}:{result['port']} - Service: {result['service']}")
                progress_bar.update(1)
    return results

# Main execution flow
if __name__ == "__main__":
    args = parse_arguments()
    try:
        ip_list = parse_ip_range(args.ip_range)
        port_list = parse_port_range(args.port_range)
    except ValueError as e:
        logging.error(f"Error parsing input ranges: {e}")
        sys.exit(1)
    
    print(f"Starting scan on {len(ip_list)} IP addresses over ports {args.port_range} using {args.threads} threads...")
    start_time = time.time()
    
    scan_results = run_scans(ip_list, port_list, args.threads, args.verbose)
    
    elapsed_time = time.time() - start_time
    print(f"\nScanning completed in {elapsed_time:.2f} seconds.")
    
    if args.output:
        try:
            with open(args.output, 'w') as outfile:
                if args.output.endswith('.json'):
                    json.dump(scan_results, outfile, indent=4)
                else:
                    for result in scan_results:
                        outfile.write(f"{result}\n")
            print(f"Results saved to {args.output}")
        except Exception as e:
            logging.error(f"Error writing results to file: {e}")