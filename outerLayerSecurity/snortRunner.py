from datetime import datetime
import re
import subprocess
import os
import hashlib
import time
from threading import Thread
import traceback

snort_bin_path = r'C:\Snort\bin'

def list_interfaces(find_Interface_subString = None):
    # If you don't know what interface your running run this.
    snort_bin_path = r'C:\Snort\bin'
    try:
        os.chdir(snort_bin_path)
        
        result = subprocess.run('.\snort -W', shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            interfaces = [line.strip() for line in result.stdout.split('\n') if line.strip()]

            foundInterface = None

            for interface in interfaces:
                if (find_Interface_subString):
                    if find_Interface_subString in interface:
                        foundInterface = interface
                        pass
                print(interface)
                
            if foundInterface:
                print(f"Found Interface. {foundInterface[0]} with substring {find_Interface_subString}")
                return int(foundInterface[0])
            else:
                print(f"No Interface was found with Substring {find_Interface_subString}")            
                
                
            return -1
        else:
            print(f'Error: {result.stderr}')
            return None

    except subprocess.CalledProcessError as e:
        print(f'Error: {e}')
        return None
    except Exception as e:
        print(f'Unexpected error: {e}')
        return None

def doesPathExist(filePath):
    return os.path.exists(filePath)

def checkDirectories(snort_Dirs):
    for dir_name, dir_path in snort_Dirs.items():
        if not doesPathExist(dir_path):
            print(f"\033[91m[ERROR] {dir_name} directory: {dir_path} does not exist.\033[0m")
        else:
            print(f"\033[92m[SUCCESS] {dir_name} directory exists.\033[0m")

def displayRules(local_rules_file_path):
    marker_count = 0
    marker_found = False

    try:
        with open(local_rules_file_path, 'r') as file:
            lines = [line.strip() for line in file]
            max_line_length = max(len(line) for line in lines)
            
            print("┌" + "─" * (max_line_length + 2) + "┐")  # Top of the box
            print(f"│ {file.name.center(max_line_length)} │")  # Header
            print("├" + "─" * (max_line_length + 2) + "┤")  # Separator
            
            for line in lines:
                if line.strip() == "#-------------":
                    marker_count += 1
                    if marker_count == 2:
                        marker_found = True
                        continue  # Skip printing the second marker line
            
                if marker_found:
                    print(f"│ {line}{' ' * (max_line_length - len(line))} │")  # Adjust spacing for each line
            
            print("└" + "─" * (max_line_length + 2) + "┘")  # Bottom of the box
    except FileNotFoundError:
        print(f"\033[91m[ERROR] {local_rules_file_path} does not exist.\033[0m")

def runSnort(snort_Dirs, interface_Number):
    snort_bin_path = snort_Dirs['Bin Directory']
    snort_config_path = snort_Dirs['Snort Configuration File']
    snort_command = fr'.\snort -i {interface_Number} -c {snort_config_path} -A full '
    full_snort_path = os.path.join(snort_bin_path, 'snort.exe')  # Assuming the executable is named snort.exe
    runas_command = fr'runas /user:Administrator "{snort_command}"'
    try:
        print("\033[93m" + f'Executing Snort Command {runas_command}' + "\033[0m")       
        print("You may be asked to enter your admin-password, in a new cmd window. Do it. ")
        os.chdir(snort_bin_path)
        subprocess.Popen(runas_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.DETACHED_PROCESS)
    except Exception as e:
        print(f'Unexpected error: {e}')

def check_file_changes(file_path, file_Check_Interval):
    extracted_data = {}

    try:
        with open(file_path, 'rb') as file:
            current_hash = hashlib.sha256(file.read()).hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return

    read_Up_To = 0

    while True:
        try:
            with open(file_path, 'rb') as file:
                new_hash = hashlib.sha256(file.read()).hexdigest()

            if new_hash != current_hash:
                print(f"File contents changed in {file_path}. New contents:")
                with open(file_path, 'r') as file:
                    fileData = file.read()
                    handle_Snort_Alerts(extracted_data, fileData, read_Up_To)
                current_hash = new_hash
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return

        time.sleep(file_Check_Interval)  

def get_Alert_ID_and_Name(alertLine):
    # Define the pattern to match the desired information
    pattern = r'\[([0-9]+:[0-9]+:[0-9]+)\]\s*([\w\s]+)\s*\[\*\*\]'

    # Use re.search to find the first match in the string
    match = re.search(pattern, alertLine)

    # Check if a match is found
    if match:
        # Extract the captured groups from the match
        number = match.group(1)
        text = match.group(2)
        return number, text.strip()  # Remove leading and trailing whitespaces from the text
    else:
        return None, None  # Return None if no match is found

def get_ip_and_time_line(ip_and_time_line):
    dateTime, src_ip, _,  dest_ip = ip_and_time_line.split()
    # date, time = dateTime.split('-')
    return dateTime, src_ip, dest_ip

def dateTime_to_ISO(dateTimeString):
    current_year = datetime.now().year
    combined_string = f'{current_year}/{dateTimeString}'
    parsed_datetime = datetime.strptime(combined_string, '%Y/%m/%d-%H:%M:%S.%f')
    iso_date = parsed_datetime.isoformat()
    return iso_date

def handle_Snort_Alerts(extracted_data, fileData, read_Up_To):
    # Will probably need to figure out when last read, in the file to avoid massive peformance issues and just reiterated over the same shit.

    entries = fileData.split('\n\n')


    entries = entries[read_Up_To:]

    for entry in entries:
        lines = entry.split('\n')
        lines = [line for line in lines if line.strip()]
        if (len(lines) > 3):
            # [**] [1:1000001:0] TEsting ICMp alert [**]
            alertLine = lines[0]
            ip_and_time_Line   = lines[2]
            try:
                alertId, alertName = get_Alert_ID_and_Name(alertLine)
                
                if (not alertId or  not alertName):
                    print("cuntty")
                    continue
                
                dateTime, src_ip, dest_ip = get_ip_and_time_line(ip_and_time_Line)

                isoDateTime = dateTime_to_ISO(dateTime)

                if src_ip.count(".") == 3 and src_ip.find(':') != -1:
                    index = src_ip.index(":")
                    src_ip = src_ip[:index]

                if src_ip not in extracted_data:
                    print(f"New Device Event. IP: {src_ip}")
                    extracted_data[src_ip] = {}
                    
                if alertName not in extracted_data[src_ip]:
                    extracted_data[src_ip][alertName] = {'count': 0, 'timeArr': []}

                extracted_data[src_ip][alertName]['count'] += 1

                # if len(extracted_data[src_ip][alertName]['timeArr']) < 10:
                #     extracted_data[src_ip][alertName]['timeArr'].append(isoDateTime)
                
            except Exception as E :
                print(f"Error at handle_Snort_Alerts {E} with string {alertLine} and entry \n {entry}")
                traceback.print_exc()
                time.sleep(10)

    read_Up_To += len(entries)

    for ip, data in extracted_data.items():
        print(f"{ip}: Data {data}")

if __name__ == '__main__':
    
    ### This file will run Snort, and print to console the threats logged by Snort. 
    
    snort_Dirs = {
        'Snort Directory':  r'C:\Snort',
        'Log Directory':    r'C:\Snort\log',
        'Rules Directory':  r'C:\Snort\rules',
        'Local Rules File': r'C:\Snort\rules\local.rules',
        'Bin Directory':    r'C:\Snort\bin',
        'Etc Directory':    r'C:\Snort\etc',
        'Alert File':       r'C:\Snort\log\alert.ids',
        'Snort Configuration File': r'c:\Snort\etc\snort.conf',
    }

    checkDirectories(snort_Dirs)
    
    alertFile = r'C:\Snort\log\alert.ids'
    
    file_Check_Interval = 2 #Checks the file for updates every x seconds. Yes theres better ways but 🥱
    interface_Number = list_interfaces(find_Interface_subString = "Ethernet Controller") # You may need to change this. When running the code, it will print ur interfaces. Add a substring from it to this.
    displayRules(snort_Dirs['Local Rules File'])
    runSnort(snort_Dirs, interface_Number=interface_Number)
    thread = Thread(target = check_file_changes, args=(snort_Dirs['Alert File'], file_Check_Interval)) # Unnecessary currently.
    thread.start()
