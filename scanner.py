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
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

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
# Sending specific queries or banners and analyzing the responses
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
    # Outside default range
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
    try:
        if port in [80, 8080, 8000, 8443]:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        elif port == 21:                                # FTP
            sock.sendall(b"USER anonymous\r\n")
        elif port == 22:                                # SSH
            sock.sendall(b"\r\n")
        elif port == 25 or port == 587:                 # SMTP
            sock.sendall(b"EHLO example.com\r\n")
        elif port == 110:                               # POP3
            sock.sendall(b"USER anonymous\r\n")
        elif port == 143 or port == 993:                # IMAP
            sock.sendall(b"TAG LOGIN user pass\r\n")
        elif port == 3306:                              # MySQL
            sock.sendall(b"\n")
        elif port == 6379:                              # Redis
            sock.sendall(b"INFO\r\n")
        elif port == 3389:                              # RDP
            sock.sendall(b"RDP\r\n")
        elif port == 5900:                              # VNC
            sock.sendall(b"RFB 003.003\r\n")
        
        response = sock.recv(1024).decode()
        logging.info(f"Open port {port} on {ip} - Detected service: {service}")
        return response
    except Exception as e:
        logging.error(f"Error Detecting service on port {port} of {ip}: {e}")
        return None

# Scan a single ip and port
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
        return None
    finally:
        sock.close()

# Simple os finger printing to identify the type of os
def os_fingerprint(ip):
    logging.info(f"Starting OS fingerprinting for {ip}")

    syn = IP(dst=ip)/TCP(dport=80, flags='S')
    try:
        syn_ack = sr1(syn, timeout=3) 

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
    
# Seperate thread to write results
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
        logging.error(f"Error whileexporting results to JSON file: {e}")

if __name__ == "__main__":
    args = parse_arguments()
    target_ip_range = args.ip_range
    port_range = range(int(args.port_range.split('-')[0]), int(args.port_range.split('-')[1]) + 1)
    thread_count = args.threads
    output_file = args.output
    verbose = args.verbose

    ip_range = [str(ip) for ip in ipaddress.IPv4Network(target_ip_range)]

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