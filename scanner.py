import socket
import logging
import threading
from queue import Queue
import ipaddress
import argparse
from scapy.all import IP, TCP, sr1, conf
from cryptography.hazmat.primitives.ciphers import algorithms

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# default Config
target_ip_range = "192.168.1.1-192.168.1.255"
port_range = range(1, 1025)
thread_count = 100
output_file = None
q = Queue()

#some global var
total_task = 0
completed_task = 0

def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced ip and Port Scanner")
    parser.add_argument("-i", "--ip-range", type=str, default=target_ip_range, help="Ip rang to scan")
    parser.add_argument("-p", "--port-range", type=str, default="1-1024", help="Port range to scan")
    parser.add_argument("-t", "--threads", type=int, default=thread_count, help="No of threads to use for scanning")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output file location (optional)")
    return parser.parse_args()

# Service Detection on some known ports
# sending specific queries or banners and analyzing the responses
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
    # outside default range
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    8000: "Common Web Service",
    8080: "HTTP Proxy",
    8443: "HTTPS Alternative",
    9000: "Custom Web Service"
}

def detect_service(ip, port):
    service = service_banners.get(port, "Unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip, port))
            
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

#function to scan a single IP's ports
def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    try:
        sock.connect((ip, port))
        response = detect_service(ip, port)
        os_info = os_fingerprint(ip)
        if response:
            return f"Open {port} on {ip} - Service Response: {response} - OS info: {os_info}"
        else:
            return f"Open {port} on {ip} - OS info: {os_info}"
    except:
        return None
    finally:
        sock.close()

#thread to handle scanning tasks
def worker():
    global completed_task 
    last_reported_progress = -1

    while not q.empty():
        ip, port = q.get()
        result = scan_port(ip, port)
        if scan_port(ip, port):
            #result = f"Open port {port} on {ip}"
            logging.info(result)
            if output_file:
                with threading.Lock():
                    with open(output_file, "a") as f:
                        f.write(result + "\n")
        
        with threading.Lock():
            completed_task += 1
        q.task_done()

#enqueue IPs and ports to scan
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

#start the scanning process
def start_scan(ip_range, ports, thread_count):
    prepare_queue(ip_range, ports)
    for _ in range(thread_count):
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()
    q.join()

#pressing enter displays current progress
def print_progress_on_enter():
    global total_task, completed_task
    while completed_task < total_task:
        input()
        with threading.Lock():
            progress = (completed_task/total_task) * 100
            print(f"Progress: {progress:.2f}% completed")


if __name__ == "__main__":
    args = parse_arguments()
    
    output_file = args.output
    
    #parsing port range
    port_start, port_end = map(int, args.port_range.split('-'))
    port_range = range(port_start, port_end + 1)

    scan_thread = threading.Thread(target=start_scan, args=(args.ip_range, port_range, args.threads))
    scan_thread.start()
    
    progress_thread = threading.Thread(target=print_progress_on_enter)
    progress_thread.start()

    scan_thread.join()
    progress_thread.join()
