import socket
import logging
import warnings
import threading
from queue import Queue
import ipaddress
import argparse
from scapy.all import IP, TCP, sr1, conf
import time
import sys
from cryptography.utils import CryptographyDeprecationWarning
from concurrent.futures import ThreadPoolExecutor
import json
from tqdm import tqdm  # Optional progress bar

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Set Scapy verbosity for detailed Scapy output (0 to suppress, 1 for some output, 2 for detailed)
conf.verb = 0

logging.basicConfig(
    level=logging.INFO,  # Changed to INFO for more detailed output
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Default Config
target_ip_range = "192.168.1.1-192.168.1.255"
port_range = range(1, 1025)
thread_count = 100
output_file = None
q = Queue()

# Some global vars
total_task = 0
completed_task = 0

scan_results = []

result_q = Queue()

# Parsing arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced IP and Port Scanner")
    parser.add_argument("-i", "--ip-range", type=str, default=target_ip_range, help="IP range to scan")
    parser.add_argument("-p", "--port-range", type=str, default="1-1024", help="Port range to scan")
    parser.add_argument("-t", "--threads", type=int, default=thread_count, help="Number of threads to use for scanning")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output file location (optional)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed output")
    return parser.parse_args()

# Service Detection on some known ports
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

# Detecting services using banner grabbing
def detect_service(sock, ip, port):
    service = service_banners.get(port, "Unknown")
    port_commands = {
        80: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        21: b"USER anonymous\r\n",
        22: b"\r\n",
        25: b"EHLO example.com\r\n",
        110: b"USER anonymous\r\n",
        143: b"TAG LOGIN user pass\r\n",
        3306: b"\n",
        6379: b"INFO\r\n",
        3389: b"RDP\r\n",
        5900: b"RFB 003.003\r\n"
    }
    
    try:
        command = port_commands.get(port, b"\r\n")
        sock.sendall(command)
        response = sock.recv(1024).decode()
        logging.info(f"Open port {port} on {ip} - Detected service: {service}")
        return response
    except Exception as e:
        logging.error(f"Error Detecting service on port {port} of {ip}: {e}")
        return None

# Scan a single IP and port
def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    try:
        sock.connect((ip, port))
        response = detect_service(sock, ip, port)
        os_info = os_fingerprint(ip)
        
        # Storing results in a dictionary
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
        logging.error(f"Error scanning port {port} on IP {ip}: {e}")
        return None
    finally:
        sock.close()

# Simple OS fingerprinting to identify the type of OS
def os_fingerprint(ip):
    logging.info(f"Starting OS fingerprinting for {ip}")
    common_ports = [80, 443, 22, 25]
    for port in common_ports:
        syn = IP(dst=ip)/TCP(dport=port, flags='S')
        try:
            syn_ack = sr1(syn, timeout=3, verbose=0) 
            if syn_ack and syn_ack.haslayer(TCP):
                tcp_layer = syn_ack.getlayer(TCP)
                ttl = syn_ack.ttl
                window_size = tcp_layer.window
                
                logging.debug(f"Received SYN-ACK with flags {tcp_layer.flags}, TTL {ttl}, Window Size {window_size}")

                if tcp_layer.flags == 0x12:  # SYN-ACK
                    if ttl <= 64:
                        return "Potential OS: Linux"
                    elif ttl <= 128:
                        return "Potential OS: Windows"
                    elif ttl <= 255:
                        return "Potential OS: Solaris/AIX"
                    else:
                        return "Unknown OS based on TTL"
                else:
                    logging.warning(f"Unexpected TCP flags: {tcp_layer.flags}")
                    return "Unknown OS"
            else:
                logging.error(f"No response or no TCP layer found for IP: {ip}")
                return "Unknown OS"
        except Exception as e:
            logging.error(f"Error during OS fingerprinting for {ip}: {e}")
            return "Unknown OS"


progress_bar = tqdm(total=total_task, desc="Scanning Progress")

# Thread to handle scanning tasks
def worker_thread(ip, port, verbose):
    global completed_task
    result = scan_port(ip, port)
    if result:
        if verbose:
            logging.info(f"Scan result: {result}")
        else:
            print(f"Open {port} on {ip} - Service Detected.")
        # Add to queue
        result_q.put(result)
    
    with threading.Lock():  # Using lock to safely update progress
        completed_task += 1
        progress_bar.update(1);
    
# Separate thread to write results
def writer_thread(output_file):
    while True:
        result = result_q.get()
        if result is None:
            break
        with threading.Lock():
            if output_file.endswith('.json'):
                scan_results.append(result)
            else:
                with open(output_file, "a") as fptr:
                    fptr.write(f"{result}\n")
        result_q.task_done()
    
    if output_file.endswith('.json'):
        export_to_json(scan_results, output_file)

# Pressing enter displays current progress
def print_progress_on_enter():
    global total_task, completed_task
    try:
        while completed_task < total_task:
            input()
            with threading.Lock():
                progress = (completed_task / total_task) * 100
                sys.stdout.write(f"\rProgress: {progress:.2f}% completed")
                sys.stdout.flush()
        print()
    except KeyboardInterrupt:
        print("\nProgress monitoring interrupted")

def export_to_json(results, file_path):
    try:
        with open(file_path, 'w') as json_file:
            json.dump(results, json_file, indent=4)
        print(f"Results successfully exported to {file_path}")
    except Exception as e:
        logging.error(f"Error while exporting results to JSON file: {e}")

# Parse IP range in 'start-end' format and return a list of IP addresses.
def parse_ip_range(ip_range_str):
    try:
        start_ip, end_ip = ip_range_str.split('-')
        start_ip = ipaddress.IPv4Address(start_ip.strip())
        end_ip = ipaddress.IPv4Address(end_ip.strip())
        if start_ip > end_ip:
            raise ValueError("Start IP should be less than or equal to End IP.")
        ip_list = [str(ip) for ip in ipaddress.summarize_address_range(start_ip, end_ip)]
        logging.debug(f"Parsed IP range: {ip_list}")
        return ip_list
    except ValueError as e:
        raise ValueError(f"Invalid IP range format: {ip_range_str}. Error: {e}")

# Parse Port range
def parse_port_range(port_range_str):
    try:
        start_port, end_port = map(int, port_range_str.split('-'))
        return range(start_port, end_port + 1)
    except ValueError as e:
        raise ValueError(f"Invalid port range format: {port_range_str}. Error: {e}")

if __name__ == "__main__":
    args = parse_arguments()
    target_ip_range = args.ip_range
    port_range = parse_port_range(args.port_range)
    thread_count = args.threads
    output_file = args.output
    verbose = args.verbose

    try:
        ip_range = parse_ip_range(target_ip_range)
    except ValueError as e:
        print(e)
        sys.exit(1)

    total_task = len(ip_range) * len(port_range)

    print(f"Starting scan on {len(ip_range)} IP addresses over ports {args.port_range} with {thread_count} threads...")

    start_time = time.time()

    # Start the progress monitoring thread
    progress_thread = threading.Thread(target=print_progress_on_enter)
    progress_thread.start()

    if output_file:
        writer = threading.Thread(target=writer_thread, args=(output_file,))
        writer.start()

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        for ip in ip_range:
            for port in port_range:
                executor.submit(worker_thread, ip, port, verbose)

    if output_file:
        result_q.put(None)  # Signal the writer thread to stop
        result_q.join()  # Wait for the writer thread to finish

    # Wait for the progress thread to finish
    progress_thread.join()

    elapsed_time = time.time() - start_time
    print(f"Scanning completed in {elapsed_time:.2f} seconds.")
