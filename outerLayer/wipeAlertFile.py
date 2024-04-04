import os, sys

def hazmat_wipe_alert_file(file_path):
    try:
        initial_line_count = 0
        
        # Count initial number of lines
        try:
            with open(file_path, 'r') as file:
                initial_line_count = len(file.readlines())
        except FileNotFoundError:
            print("File not found at path:", file_path)
            return False
        
        # Wipe the contents of the file
        try:
            with open(file_path, 'w') as file:
                file.truncate(0)
        except FileNotFoundError:
            print("File not found at path:", file_path)
            return False
        

        # Message to print
        message = f"Contents of {file_path} have been wiped. Deleted {initial_line_count} lines."
        # Length of message
        message_length = len(message)
        
        # Create box dynamically
        print("╔" + "═" * (message_length + 2) + "╗")
        print("║ " + message + " ║")
        print("╚" + "═" * (message_length + 2) + "╝")
    except Exception as e:
        print("An error occurred:", e)
        return False

if __name__ == "__main__":
    file_path = "C:\\Snort\\log\\alert.ids"
    hazmat_wipe_alert_file(file_path)
