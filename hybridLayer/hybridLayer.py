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
        self.devices = {}
        self.threatTable = {
            "portScanning": 0.2,
            "pinging":      0.9,
        }
        
        self.threshold = 0.25
        
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

                self.basic_correlation()
                
                # self.analyze_log_in()
                
                ###### Analyzer Functions ######
                
                self.display_Events_and_calc_threat_level()
                    
                start_time = time.time()
                self.database.disconnect()


    def basic_correlation(self):
        threatType = "Basic Threat"

        ipThreatLevels       = self.database.get_ip_threat_levels()
        usernameThreatLevels = self.database.get_username_threat_levels()
        

        
        
        print(ipThreatLevels)
        print(usernameThreatLevels)


        



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

            self.add_threat(IP, ips_by_username + " " + datetime_string,  threatType)






    def find_matching_usernames(self, ip_address, user_ip_dict):
        matching_usernames = []
        for username, ip_list in user_ip_dict.items():
            if ip_address in ip_list:
                matching_usernames.append(username)
        return matching_usernames


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
        results = self.database.execute_query(f"SELECT DISTINCT ip_address from hybrid_idps.HybridLayer")
        ip_addresses = [ip['ip_address'] for ip in results]
        for ip in ip_addresses:
            self.devices[ip] = {'threatLevel': 0, 'logs': {}}
                
    def add_threat(self, ip_address, logName,  log):
        if ip_address in self.devices:
            device = self.devices[ip_address]
            device['logs'][logName] = log
        else:
            print(f"Device with IP address {ip_address} does not exist.")
            
    def set_threat_level(self, ip_address, newThreatLevel):
        if ip_address in self.devices:
            device = self.devices[ip_address]['threatLevel'] = newThreatLevel
        else:
            print(f"Device with IP address {ip_address} does not exist.")

if __name__ == "__main__":
    x = HybridLayer()

        
            