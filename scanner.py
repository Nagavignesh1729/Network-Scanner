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

        with threading.Lock():
            scan_results.append(result)

        if response:
            return f"Open {port} on {ip} - Service Response: {response} - OS info: {os_info}"
    
    except socket.timeout:
        logging.warning(f"Port {port} on {ip} timed out.")
        return None
    except Exception as e:
        logging.error(f"Error while scanning port {port} on {ip}: {e}")
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
            logging.info(result)
        else:
            print(f"Open {port} on {ip} - Service Detected.")
        #Writes output to a file (appends it)
        if output_file:
            with threading.Lock():
                with open(output_file, "a") as f:
                    f.write(result + "\n")
    
    with threading.Lock():  # Using lock to safely update progress
        completed_task += 1

# Enqueue IPs and ports to scan
def prepare_queue(ip_range, ports):
    global total_task 

    start_ip, end_ip = ip_range.split('-')
    start_ip = ipaddress.ip_address(start_ip)
    end_ip = ipaddress.ip_address(end_ip)

    for ip_int in range(int(start_ip), int(end_ip) + 1):
        ip = str(ipaddress.ip_address(ip_int))
        for port in ports:
            q.put((ip, port))
            total_task += 1

# Start the scanning process
def start_scan(ip_range, ports, thread_count, verbose=False):
    prepare_queue(ip_range, ports)

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = []
        while not q.empty():
            ip, port = q.get()
            futures.append(executor.submit(worker_thread, ip, port, verbose))

        # Wait for all futures to complete
        for future in as_completed(futures):
            future.result()

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

if __name__ == "__main__":
    args = parse_arguments()
    
    output_file = args.output
    verbose = args.verbose
    
    # Parsing port range
    port_start, port_end = map(int, args.port_range.split('-'))
    port_range = range(port_start, port_end + 1)

    # Preparing the thread and starting it
    scan_thread = threading.Thread(target=start_scan, args=(args.ip_range, port_range, args.threads, verbose))
    scan_thread.start()
    
    # A seperate thread to listen for user input to print current progress
    progress_thread = threading.Thread(target=print_progress_on_enter)
    progress_thread.start()

    scan_thread.join()
    progress_thread.join()