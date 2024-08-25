import socket
import logging
import threading
from queue import Queue
import ipaddress
import argparse

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Configurations
target_ip_range = "192.168.1.1-192.168.1.255"
port_range = range(1, 1025)
thread_count = 100
q = Queue()
output_file = None

def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced ip and Port Scanner")
    parser.add_argument("-i", "--ip-range", type=str, default=target_ip_range, help="Ip rang to scan")
    parser.add_argument("-p", "--port-range", type=str, default="1-1024", help="Port range to scan")
    parser.add_argument("-t", "--threads", type=int, default=thread_count, help="No of threads to use for scanning")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output file location (optional)")
    return parser.parse_args()

# Service Detection on some known ports
# sending specific queries or banners and analyzing the responses
def detect_service(ip, port):
    service_banners = {
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        23: "Telnet"
    }
    service = service_banners.get(port, "Unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip, port))
            if port in service_banners:
                if port in [80, 443]:
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                elif port in [21]:
                    sock.sendall(b"USER anonymous\r\n")
                elif port in [22]:
                    pass

                response = sock.recv(1024).decode()
                logging.info(f"Open port {port} on {ip} - Detected service: {service}")
                return response
            else:
                return None
    except Exception as e:
        logging.error(f"Error Detecting service on port {port} of {ip}: {e}")
        return None

#function to scan a single IP's ports
def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    try:
        sock.connect((ip, port))
        response = detect_service(ip, port)
        if response:
            return f"Open {port} on {ip} - Service Response: {response}"
        else:
            return f"Open {port} on {ip}"
    except:
        return None
    finally:
        sock.close()

#thread to handle scanning tasks
def worker():
    while not q.empty():
        ip, port = q.get()
        if scan_port(ip, port):
            result = f"Open port {port} on {ip}"
            logging.info(result)
            if output_file:
                with threading.Lock():
                    with open(output_file, "a") as f:
                        f.write(result + "\n")
        q.task_done()

#enqueue IPs and ports to scan
def prepare_queue(ip_range, ports):
    start_ip, end_ip = ip_range.split('-')
    start_ip = ipaddress.ip_address(start_ip)
    end_ip = ipaddress.ip_address(end_ip)

    for ip_int in range(int(start_ip), int(end_ip) + 1):
        ip = str(ipaddress.ip_address(ip_int))
        for port in ports:
            q.put((ip, port))

#start the scanning process
def start_scan(ip_range, ports, thread_count):
    prepare_queue(ip_range, ports)
    for _ in range(thread_count):
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()
    q.join()

if __name__ == "__main__":
    args = parse_arguments()
    
    output_file = args.output
    # Parse the port range
    port_start, port_end = map(int, args.port_range.split('-'))
    port_range = range(port_start, port_end + 1)
    
    start_scan(args.ip_range, port_range, args.threads)