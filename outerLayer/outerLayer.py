import subprocess
import time
import importlib
import json
import sys, os
sys.path.append(os.path.abspath("../helperFiles"))
from sqlConnector import MySQLConnection 

try:
    import mysql.connector
except ImportError:
    print("\033[91mmysql.connector is not installed. Run 'pip install mysql-connector-python' \033[0m")



class OuterLayer():
    def __init__(self) -> None:
        self.database = MySQLConnection(host='localhost', user='Hybrid_IDPS', password='css2', database='hybrid_idps')
        self.database.setVerbose(False)
        self.database.hazmat_wipe_Table('outerLayerThreats')
        self.remove_firewall_rules()
        self.devices = {}
        self.ban_threshold = 1
        self.threatTable = {
            "Port Scanning": 0.3,
            "TCP Flood Attack": 0.6,
            "UDP Flood Attack": 0.6,
            "ICMP Flood Attack": 0.6,
            "SSH Brute Force Attack": 0.4,
            "Unusual Incoming Traffic": 0.1,
            "Unusual Outgoing Traffic": 0.1,
            "Suspicious Port Activity": 0.1,
            
        }

        self.ipBanList = []
        self.locationBanList = [
            "Prague",
            "Minsk",
            "New Zealand",
            "North Korea",
            "Romania"
        ]


        self.central_analyzer()
        
 

    def central_analyzer(self):
        interval = 1
        start_time = time.time()
        while True:
            if time.time() - start_time >= interval:
                self.database.connect()
                self.add_devices()
                ###### Analyzer Functions ######
                
                self.analyze_port_scanning()
                
                self.analyze_tcp_flood() #TODO
                
                self.analyze_udp_flood() #TODO

                self.analyze_icmp_flood() #TODO

                self.analyze_ssh_brute_force() #TODO
                
                self.analyze_unusual_incoming_geolocation()

                self.analyze_unusual_outgoing_geolocation()
                



                ###### Analyzer Functions ######
                
                self.ipBanList = self.database.get_banned_ips(self.ban_threshold)

                self.display_Events_and_calc_threat_level()
                
                # self.database.get_banned_ips(self.ban_threshold)
                
                self.generate_firewall_rules(self.ipBanList)

                start_time = time.time()
                self.database.disconnect()
                
                
    def analyze_event_type(self, event_type, threat_name, threshold):
        results = self.database.execute_query(f"SELECT * FROM hybrid_idps.outerLayer WHERE event_type = %s AND processed = False ORDER BY timestamp DESC", (event_type,))
        results = self.extract_ips(results)
        for ip, all_events in results.items():
            count = 0
            for event in all_events:
                count += 1
                if count > threshold:
                    log_name = f"{threat_name}-{event['timestamp']}"
                    self.add_threat(ip, log_name, event['geolocation'], event['timestamp'], threat_name)
                    count = 0
                self.database.execute_query(f"UPDATE hybrid_idps.outerLayer SET processed = True WHERE ip_address = %s AND event_type = %s", (ip, event_type))


    def analyze_port_scanning(self):
        event_type = 'Possible Port Scanning'
        threat_name = "Port Scanning"
        threshold = 200
        self.analyze_event_type(event_type, threat_name, threshold)


    def analyze_tcp_flood(self):
        event_types = ['Possible SYN Flood', 'Possible ACK Flood', 'Possible RST Flood', 'Possible FIN Flood']
        threat_name = "TCP Flood Attack"
        threshold = 10000
        for event_type in event_types:
            self.analyze_event_type(event_type, threat_name, threshold)


    def analyze_udp_flood(self):
        event_type = 'Possible UDP Flood'
        threat_name = "UDP Flood Attack"
        threshold = 10000
        self.analyze_event_type(event_type, threat_name, threshold)


    def analyze_icmp_flood(self):
        event_type = 'Possible ICMP Flood'
        threat_name = "ICMP Flood Attack"
        threshold = 10000
        self.analyze_event_type(event_type, threat_name, threshold)


    def analyze_ssh_brute_force(self):
        event_type = 'Possible SSH Brute Force'
        threat_name = "SSH Brute Force Attack"
        threshold = 10
        self.analyze_event_type(event_type, threat_name, threshold)


    def analyze_unusual_incoming_geolocation(self):
        event_types = ['Incoming TCP Traffic', 'Incoming UDP Traffic','Suspicious Port Activity']
        threatName = "Unusual Incoming Traffic"
        
        # Define your threshold for determining what constitutes unusual traffic
        threshold = 10  # Placeholder threshold, adjust as needed
        
        for event_type in event_types:
            results = self.database.execute_query(f"SELECT * FROM hybrid_idps.outerLayer WHERE event_type = '{event_type}' AND processed = False ORDER BY timestamp DESC")
            results = self.extract_ips(results)
           

            for ip, all_events in results.items():
                count = 0
                for event in all_events:
                    count += 1

                    # Check if the geolocation is in the list of unusual geolocations
                    if event['geolocation'] in self.locationBanList:
                        if count > threshold:
                            logName = f"{threatName}-{event['timestamp']}"
                            self.add_threat(ip, logName, event['geolocation'], event['timestamp'], threatName)
                            count = 0
                        
                        self.database.execute_query(f"UPDATE hybrid_idps.outerLayer SET processed = True WHERE ip_address = '{ip}' AND event_type = '{event_type}'")

    def analyze_unusual_outgoing_geolocation(self): 
        event_types = ['Suspicious Port Activity']
        threatName = "Unusual Outgoing Traffic"
        
        # Define your threshold for determining what constitutes unusual traffic
        threshold = 10  # Placeholder threshold, adjust as needed
        
        for event_type in event_types:
            results = self.database.execute_query(f"SELECT * FROM hybrid_idps.outerLayer WHERE event_type = '{event_type}' AND processed = False ORDER BY timestamp DESC")
            results = self.extract_ips(results)
            for ip, all_events in results.items():
                count = 0
                for event in all_events:
                    count += 1

                    # Check if the geolocation is in the list of unusual geolocations
                    if event['geolocation'] in self.locationBanList:
                        if count > threshold:
                            logName = f"{threatName}-{event['timestamp']}"
                            self.add_threat(ip, logName, event['geolocation'], event['timestamp'], threatName)
                            count = 0
                        
                        self.database.execute_query(f"UPDATE hybrid_idps.outerLayer SET processed = True WHERE ip_address = '{ip}' AND event_type = '{event_type}'")
    

    def display_Events_and_calc_threat_level(self):
        for ip, deviceData in self.devices.items():
            print("\n")
            print(f"IP: {ip}")
            logs = deviceData["logs"]
            threatLevel = 0
            for threatName, threadType in logs.items():
                print(f"        {threatName}")
                threatLevel += self.threatTable[threadType]
                
            if threatLevel > 1: threatLevel = 1
            self.set_threat_level(ip, threatLevel)
            color_code = "\033[92m"  # Green
            
            if 0 < threatLevel < 0.5:
                color_code = "\033[93m"  # Yellow
            elif threatLevel >= 0.5:
                color_code = "\033[91m"  # Red
                
            reset_color = "\033[0m"
            print(f"    {color_code}[Threat Level]:   {threatLevel} {reset_color}")
        
            
    def extract_ips(self, results):
        ip_dict = {}
        for entry in results:
            ip = entry['ip_address']
            if ip not in ip_dict:
                ip_dict[ip] = []
            ip_dict[ip].append(entry)
        return ip_dict

    def add_devices(self):
        results = self.database.execute_query(f"SELECT DISTINCT ip_address from hybrid_idps.outerLayer")
        ip_addresses = [ip['ip_address'] for ip in results]
        for ip in ip_addresses:
            if ip not in self.devices:
                self.devices[ip] = {'threatLevel': 0, 'logs': {}}
                
    def add_threat(self, ip_address, logName, geolocation, timestamp, threatName):
        if ip_address in self.devices:
            device = self.devices[ip_address]
            threatLevel = self.threatTable[threatName]
            
            if logName not in device['logs']:
                print('adds')
                print(device['logs'])
                device['logs'][logName] = threatName
                self.database.add_threat_to_outer_Layer_Threats_DB(ip_address, logName, geolocation, timestamp, threatName, threatLevel)
            
        else:
            print(f"Device with IP address {ip_address} does not exist.")
            
    def set_threat_level(self, ip_address, newThreatLevel):
        if ip_address in self.devices:
            device = self.devices[ip_address]['threatLevel'] = newThreatLevel
        else:
            print(f"Device with IP address {ip_address} does not exist.")

    def run_powershell_as_admin(self, command):
        # Create a subprocess with administrative privileges
        process = subprocess.Popen(['powershell.exe', '-Command', command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, command, output=output, stderr=error)
        return output.decode('utf-8')

    def generate_firewall_rules(self, banned_ips):
        existing_rules = self.get_existing_firewall_rules()  # Get existing firewall rules
        
        powershell_commands = []
        for ip in banned_ips:
            # Check if a rule for the IP already exists
            if not any(f"Block Snort Inbound {ip}" in rule or f"Block Snort Outbound {ip}" in rule for rule in existing_rules):
                # Create PowerShell commands to block inbound and outbound traffic from the banned IP
                powershell_commands.append(f'New-NetFirewallRule -DisplayName "Block Snort Inbound {ip}" -Direction Inbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress {ip}')
                powershell_commands.append(f'New-NetFirewallRule -DisplayName "Block Snort Outbound {ip}" -Direction Outbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress {ip}')
            
        # Execute all PowerShell commands as administrator
        for cmd in powershell_commands:
            try:
                self.run_powershell_as_admin(cmd)
            except subprocess.CalledProcessError as e:
                print(f"Error executing PowerShell command: {e}")
                # Handle the error here, such as logging or displaying an error message to the user

    def get_existing_firewall_rules(self):
        # PowerShell command to get existing firewall rules with "Block Snort" in the display name
        try:
            # Run PowerShell command
            output = self.run_powershell_as_admin("Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'Block Snort*' } | Select-Object -ExpandProperty DisplayName")
            # Split the output by newline to get individual rule names
            existing_rule_names = output.strip().split('\n')
            return existing_rule_names
        except subprocess.CalledProcessError as e:
            print(f"Error executing PowerShell command: {e}")
            # Handle the error here, such as logging or displaying an error message to the user
            return []

    def remove_firewall_rules(self):
        try:
            # Remove all firewall rules with display names containing "Block Snort" as administrator
            self.run_powershell_as_admin("Remove-NetFirewallRule -DisplayName 'Block Snort*'")
            print("Firewall rules removed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error removing firewall rules: {e}")
            # Handle the error here, such as logging or displaying an error message to the user


if __name__ == "__main__":
    x = OuterLayer()
