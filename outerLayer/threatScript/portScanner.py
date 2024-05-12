import socket
import threading
import time
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def scan_port(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            print(f"Port {port}: {GREEN}Open{RESET}")
        else:
            print(f"Port {port}: {RED}Closed{RESET}")
        s.close()
    except socket.error:
        print("Error occurred while scanning port")

def port_scan(target_ip, start_port, end_port):
    print(f"Scanning ports on {target_ip}...\n")
    for port in range(start_port, end_port + 1):
        threading.Thread(target=scan_port, args=(target_ip, port)).start()
        time.sleep(0.01)

if __name__ == "__main__":
    target_ip = "192.168.1.123"
    start_port = 2900
    end_port   = 8900
    port_scan(target_ip, start_port, end_port)
