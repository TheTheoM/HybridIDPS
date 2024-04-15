import time
import importlib
import json
import sys, os
from datetime import datetime

sys.path.append(os.path.abspath("../helperFiles"))
from sqlConnector import MySQLConnection 
try:
    import mysql.connector
except ImportError:
    print("\033[91mmysql.connector is not installed. Run 'pip install mysql-connector-python' \033[0m")

class HybridLayer():
    def __init__(self) -> None:
        self.database = MySQLConnection()
        self.database.hazmat_wipe_Table("HybridLayer")
        self.devices = {}
        self.threatTable = {
            "Basic-Hybrid-Threat": 0.2,
            "pinging":      0.9,
            "SSH comprimised": 0.8
        }
        
        self.threshold = 0.2
        self.ban_threshold = 0.7
        
        self.central_analyzer()

    def central_analyzer(self):
        interval = 1
        start_time = time.time()
        while True:
            if time.time() - start_time >= interval:
                self.database.connect()
                self.add_devices()
                ###### Analyzer Functions ######
                
                # self.database.get_banned_ips()

                self.extract_json_threat()

                self.basic_correlation()
                
                # self.analyze_log_in()
                

                ###### Analyzer Functions ######
                
                self.display_Events_and_calc_threat_level()
                    
                start_time = time.time()
                self.database.disconnect()

    def basic_correlation(self):
        threatType = "Basic-Hybrid-Threat"
        ipThreatLevels       = self.database.get_ip_threat_levels()
        usernameThreatLevels = self.database.get_username_threat_levels()
        common_keys = set(ipThreatLevels.keys()).intersection(usernameThreatLevels.keys()) # Find the intersection of the keys
        common_items = {key: (ipThreatLevels[key], usernameThreatLevels[key]) for key in common_keys}

        for ip, value in common_items.items():
            
            outerLayerData, innerLayerData = value
            threat_level_outer, timeStamp_outer = outerLayerData.values()
            threat_level_inner, timeStamp_inner, username = innerLayerData.values()
            combined_threat_level = threat_level_outer + threat_level_inner

            if combined_threat_level > self.threshold:

                if timeStamp_outer > timeStamp_inner:
                    most_recent = timeStamp_outer
                else:
                    most_recent = timeStamp_inner
                self.add_threat(ip, username, f"{threatType} {most_recent}", threatType, threat_level_outer, threat_level_inner)

    def basic_correlation_old(self):
        threatType = "Basic Threat"
        
        usernames = self.database.get_usernames_above_threshold(self.threshold)
        # print(usernames)
        ips_by_username = self.database.get_inner_ips_by_username(usernames)
        # print(f'Inner Layer Threats: {ips_by_username}')
        threatIps_outerLayer = self.database.get_banned_ips(self.threshold, False)
        # print(f'Outer Layer Threats: {threatIps_outerLayer}')
        for IP in threatIps_outerLayer:
            susUsername = self.find_matching_usernames(IP, ips_by_username)
            # print(f'Hybrid Threat: {susUsername}')
            current_datetime = datetime.now()
            datetime_string = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

            # self.add_threat(IP, susUsername, ips_by_username + " " + datetime_string,  threatType)

    def find_matching_usernames(self, ip_address, user_ip_dict):
        matching_usernames = []
        for username, ip_list in user_ip_dict.items():
            if ip_address in ip_list:
                matching_usernames.append(username)
        return matching_usernames

    def display_Events_and_calc_threat_level(self):
        for ip_and_username, deviceData in self.devices.items():
            print()
            print(f"{ip_and_username}:")
            
            logs = deviceData["logs"]
            for logName, logData in logs.items():
                log, threat_level_outer, threat_level_inner, combinedThreatLevel = logData.values()

                color_code = "\033[92m"      # Green
                
                if 0 < combinedThreatLevel < 0.5:
                    color_code = "\033[93m"  # Yellow
                elif combinedThreatLevel >= 0.5:
                    color_code = "\033[91m"  # Red
                    
                reset_color = "\033[0m"
                print(f"    {log}   {color_code}[Threat Level]: {combinedThreatLevel}  [Inner: {threat_level_inner}  Outer: {threat_level_outer}] {reset_color}")
            
    def extract_ips(self, results):
        ip_dict = {}
        for entry in results:
            ip = entry['ip_address']
            if ip not in ip_dict:
                ip_dict[ip] = []
            ip_dict[ip].append(entry)
        return ip_dict
    
    def extract_json_threat(self):
        
        innerLayer_Threats = self.database.execute_query(f"SELECT * FROM hybrid_idps.innerLayerThreats WHERE event_type = 'jsonComprimised'")
        if(len(innerLayer_Threats) >0):

            outerLayer_Threats = self.database.execute_query(f"SELECT * FROM hybrid_idps.outerLayerThreats WHERE threatName = 'SSH Login'")

            if(len(outerLayer_Threats) > 0):
                print("ssh and json comprimised")
                # print(innerLayer_Threats['username'])
                self.add_threat(outerLayer_Threats[0]['ip_address'],innerLayer_Threats[0]['username'], f"{innerLayer_Threats[0]['payload']} {outerLayer_Threats[0]['timestamp']}", 
                                "ssh", outerLayer_Threats[0]['threat_level'], innerLayer_Threats[0]['threat_level'])
            # return innerLayer_Threats, outerLayer_Threats

    

    def add_devices(self):
        results = self.database.execute_query(f"SELECT DISTINCT ip_address from hybrid_idps.hybridLayer")
        ip_addresses = [ip['ip_address'] for ip in results]
        for ip_and_username in ip_addresses:
            self.devices[ip_and_username] = {'threatLevel': 0, 'logs': {}}

    def add_threat(self, IP, username, logName, log, threat_level_outer, threat_level_inner):
        ip_and_username = f"{IP} - {username}"
        combinedThreatLevel = threat_level_outer + threat_level_inner

        if ip_and_username not in self.devices:
            self.devices[ip_and_username] = {'logs': {}}

        device = self.devices[ip_and_username]
        
        if logName in device['logs']:
            oldThreatLevel = device['logs'][logName]['combinedThreatLevel']

            if oldThreatLevel != combinedThreatLevel:
                device['logs'][logName] = {'log': log, "threat_level_outer":  threat_level_outer,
                                                                    "threat_level_inner":  threat_level_inner,
                                                                    "combinedThreatLevel": combinedThreatLevel}
                
                if combinedThreatLevel > self.ban_threshold:
                    self.print_box(f"[Banned on Outer & Inner Layer]: {IP} | {username}")
                    self.database.add_event_to_Hybrid_DB(username, IP, None)

                
        else:
            device['logs'][logName] = {'log': log, "threat_level_outer":  threat_level_outer,
                                                                            "threat_level_inner":  threat_level_inner,
                                                                            "combinedThreatLevel": combinedThreatLevel}
            if combinedThreatLevel > self.ban_threshold:
                self.print_box(f"[Banned on Outer & Inner Layer]: {IP} | {username}")
                self.database.add_event_to_Hybrid_DB(username, IP, None)

    

        



  
    def print_box(self, text):
        width = len(text) + 2 
        print(" " + "_" * width)
        print(f"| {text} |")
        print(" " + "‾" * width)

if __name__ == "__main__":
    x = HybridLayer()

        
            