import socket
import threading
from queue import Queue

# Config
target_ip_range = "192.168.1.1-192.168.1.255"
port_range = range(1, 1025)
thread_count = 100
q = Queue()

#function to scan a single ip
def scan_ip(ip):
    try:
        socket.gethostbyaddr(ip)
        return True
    except socket.herror:
        return False

#function to scan ports for a given ip
def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    try:
        sock.connect((ip, port))
        return True
    except:
        return False
    finally:
        sock.close()

#thread to handle scanning tasks
def worker():
    while not q.empty():
        ip, port = q.get()
        if scan_ip(ip) and scan_port(ip, port):
            print(f"Open port {port} on {ip}")
        q.task_done()

#Enqueue IPs and ports to scan
def prepare_queue():
    ip_base = ".".join(target_ip_range.split(".")[:-1])
    for i in range(int(target_ip_range.split(".")[-2]), int(target_ip_range.split(".")[-1]) + 1):
        ip = f"{ip_base}.{i}"
        for port in port_range:
            q.put((ip, port))

# Start the scanning process
def start_scan():
    prepare_queue()
    for _ in range(thread_count):
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()
    q.join()

if __name__ == "__main__":
    start_scan()
