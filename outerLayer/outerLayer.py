import time
import importlib
import json
import sys, os
sys.path.append(os.path.abspath("../helperFiles"))
from sqlConnector import MySQLConnection 
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
        }
        self.central_analyzer()
        self.locationBanList = {
            "Prague"
            "Minsk"
            "New Zealand"
        }
        self.ipBanList = {              }

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

                #self.analyze_unusual_outgoing_geolocation()
                
                ###### Analyzer Functions ######
                
                
                self.display_Events_and_calc_threat_level()
                
                self.database.get_banned_ips(self.ban_threshold)

                start_time = time.time()
                self.database.disconnect()

    def analyze_port_scanning(self):
        event_type = 'Possible Port Scanning'
        threatName = "Port Scanning"
        
        scanningCountThreshold = 200
        
        results = self.database.execute_query(f"SELECT * from hybrid_idps.outerLayer WHERE event_type = '{event_type}' ORDER BY timestamp DESC")
        results = self.extract_ips(results)
        for ip, all_events in results.items():
            count = 0
            for event in all_events:
                count += 1

                if count > scanningCountThreshold:
                    logName = f"{threatName}-{event['timestamp']}"
                    # self.add_threat(ip, logName, all_events[:1])
                    self.add_threat(ip, logName, event['geolocation'], event['timestamp'], threatName)
                    count = 0

    def analyze_tcp_flood(self):
        event_types = ['Possible SYN Flood', 'Possible ACK Flood', 'Possible RST Flood', 'Possible FIN Flood']
        threatName = "TCP Flood Attack"
        
        threshold = 10000
        
        for event_type in event_types:
            results = self.database.execute_query(f"SELECT * from hybrid_idps.outerLayer WHERE event_type = '{event_type}' ORDER BY timestamp DESC")
            results = self.extract_ips(results)
            for ip, all_events in results.items():
                count = 0
                for event in all_events:
                    count += 1

                    if count > threshold:
                        logName = f"{threatName}-{event['timestamp']}"
                        self.add_threat(ip, logName, event['geolocation'], event['timestamp'], threatName)
                        count = 0


    def analyze_udp_flood(self):
        event_type = 'Possible UDP Flood'
        threatName = "UDP Flood Attack"
        
        threshold = 10000
        
        results = self.database.execute_query(f"SELECT * from hybrid_idps.outerLayer WHERE event_type = '{event_type}' ORDER BY timestamp DESC")
        results = self.extract_ips(results)
        for ip, all_events in results.items():
            count = 0
            for event in all_events:
                count += 1

                if count > threshold:
                    logName = f"{threatName}-{event['timestamp']}"
                    self.add_threat(ip, logName, event['geolocation'], event['timestamp'], threatName)
                    count = 0

    def analyze_icmp_flood(self):
        event_type = 'Possible ICMP Flood'
        threatName = "ICMP Flood Attack"
        
        threshold = 10000
        
        results = self.database.execute_query(f"SELECT * from hybrid_idps.outerLayer WHERE event_type = '{event_type}' ORDER BY timestamp DESC")
        results = self.extract_ips(results)
        for ip, all_events in results.items():
            count = 0
            for event in all_events:
                count += 1

                if count > threshold:
                    logName = f"{threatName}-{event['timestamp']}"
                    self.add_threat(ip, logName, event['geolocation'], event['timestamp'], threatName)
                    count = 0

    def analyze_ssh_brute_force(self):
        event_type = 'Possible SSH Brute Force'
        threatName = "SSH Brute Force Attack"
        
        threshold = 10
        
        results = self.database.execute_query(f"SELECT * from hybrid_idps.outerLayer WHERE event_type = '{event_type}' ORDER BY timestamp DESC")
        results = self.extract_ips(results)
        for ip, all_events in results.items():
            count = 0
            for event in all_events:
                count += 1

                if count > threshold:
                    logName = f"{threatName}-{event['timestamp']}"
                    self.add_threat(ip, logName, event['geolocation'], event['timestamp'], threatName)
                    count = 0

    
    
    def analyze_unusual_incoming_geolocation(self):
        event_types = ['Outgoing TCP Traffic', 'Outgoing UDP Traffic']
        threatName = "Unusual Incoming Traffic"
        
        # Define your threshold for determining what constitutes unusual traffic
        threshold = 5  # Placeholder threshold, adjust as needed
        
        
        
        for event_type in event_types:
            results = self.database.execute_query(f"SELECT * from hybrid_idps.outerLayer WHERE event_type = '{event_type}' ORDER BY timestamp DESC")
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

    def analyze_unusual_outgoing_geolocation(self): 
        event_types = ['Outgoing TCP Traffic', 'Outgoing UDP Traffic']
        threatName = "Unusual Incoming Traffic"
        
        # Define your threshold for determining what constitutes unusual traffic
        threshold = 5  # Placeholder threshold, adjust as needed
        
        for event_type in event_types:
            results = self.database.execute_query(f"SELECT * from hybrid_idps.outerLayer WHERE event_type = '{event_type}' ORDER BY timestamp DESC")
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
            if threatLevel > 0.5:
                color_code = "\033[91m"  # Red
            elif 0 < threatLevel < 0.5:
                color_code = "\033[93m"  # Yellow
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


if __name__ == "__main__":
    x = OuterLayer()

        
            