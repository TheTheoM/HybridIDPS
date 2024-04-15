import time
from datetime import datetime, timedelta, timezone
import json
import importlib
import sys, os
sys.path.append(os.path.abspath("../helperFiles"))
from sqlConnector import MySQLConnection 

try:
    import mysql.connector
except ImportError:
    print("\033[91mmysql.connector is not installed. Run 'pip install mysql-connector-python' \033[0m")

class InnerLayer():
    def __init__(self) -> None:
        self.database = MySQLConnection()
        self.database.setVerbose(False)
        self.database.hazmat_wipe_Table('innerLayer')
        self.database.hazmat_wipe_Table('innerLayerThreats')
        self.devices = {}
        # self.threat_counts = {} #This may needs to be removed, work in progress
        self.threatTable = {
            "spamCredentials":     0.1,
            "massReporting":       0.2,
            "massAccountCreation": 1,
            "payloadAttack": 1,
            "sqlInjection": 0.6,
            "jsonComprimised": 0.5,
        }
        self.central_analyzer()

    def central_analyzer(self):
        interval = 1
        start_time = time.time()

        while True:
            if time.time() - start_time >= interval:
                self.database.connect()
                self.add_devices()
                ###### Analyzer Functions ######
                
                self.check_like_mismatch()

                self.analyze_spam_credentials()

                self.analyze_mass_reporting()

                self.analyze_mass_account_creation_ip()

                

                
                self.check_payload_increment()
                
                self.check_like_mismatch()
  
                ###### Analyzer Functions ######

                self.display_Events_and_calc_threat_level()
                start_time = time.time()
                self.database.disconnect()
                
       
        


    def analyze_spam_credentials(self):
        event_type = 'invalidCredentials'
        threatName = "spamCredentials"
        threshold = 20
        time_frame = 1 #Minutes
        current_time = datetime.now(timezone.utc)
        time_limit = current_time - timedelta(minutes=time_frame)

        threat_level = self.threatTable[threatName]
        results = self.database.execute_query(f"SELECT * FROM hybrid_idps.innerLayer WHERE event_type = '{event_type}' AND timestamp >= '{time_limit.strftime('%Y-%m-%d %H:%M:%S')}' ORDER BY timestamp DESC")
        results = self.extract_user(results)

        for user, all_events in results.items():
            count = 0
            for event in all_events:
                count += 1
                if count > threshold:
                    logName = f"{threatName}-{event['timestamp']}"
                    self.add_threat(logName, threatName,  event['username'], event['target_username'], event['ip_address'], event['geolocation'], event['timestamp'],
                                    threatName, threat_level, event['payload'])
                    count = 0

    def analyze_mass_reporting(self):
        event_type = 'reportUserByUsername'
        threatName = "massReporting"
        threshold = 2
        time_frame = 2 #Minutes
        current_time = datetime.now(timezone.utc)
        time_limit = current_time - timedelta(minutes=time_frame)

        threat_level = self.threatTable[threatName]
        results = self.database.execute_query(f"SELECT * FROM hybrid_idps.innerLayer WHERE event_type = '{event_type}' AND timestamp >= '{time_limit.strftime('%Y-%m-%d %H:%M:%S')}' ORDER BY timestamp DESC")
        results = self.extract_user(results)

        for user, user_events in results.items():
            count = 0
            for event in user_events:
                    count += 1
                    if count > threshold:
                        logName = f"{threatName}-{event['timestamp']}"
                        self.add_threat(logName, threatName,  event['username'], event['target_username'], event['ip_address'], event['geolocation'], event['timestamp'],
                                        threatName, threat_level, event['payload'])
                        count = 0

    def analyze_mass_account_creation_ip(self):   
        event_type = 'registrationSuccess'
        threatName = "massAccountCreation"
        threshold = 50
        time_frame = 2 #Minutes
        current_time = datetime.now(timezone.utc)
        time_limit = current_time - timedelta(minutes=time_frame)

        threat_level = self.threatTable[threatName]
        results = self.database.execute_query(f"""SELECT ip_address, COUNT(username) AS registration_count
                                                FROM hybrid_idps.innerLayer 
                                                WHERE event_type = '{event_type}' 
                                                AND timestamp >= '{time_limit.strftime('%Y-%m-%d %H:%M:%S')}'
                                                GROUP BY ip_address
                                                HAVING COUNT(username) >= {threshold}""")
        results = self.extract_ips(results)

        for ip, all_event in results.items():
            if all_event[0]['registration_count'] > 1:
                usernames_result = self.database.execute_query(f""" SELECT *
                                                                    FROM hybrid_idps.innerLayer
                                                                    WHERE ip_address = '{ip}'
                                                                    AND event_type = '{event_type}'
                                                                    AND timestamp >= '{time_limit.strftime('%Y-%m-%d %H:%M:%S')}'""")
                usernames = self.extract_user(usernames_result)

                for user in usernames:
                    logName = f"{threatName}"
                    self.add_threat(logName, threatName,  user, None, ip, None, None,
                                    threatName, threat_level, None)

    def check_payload_increment(self):
        event_type = 'likePost'
        threatName = "payloadAttack"

        threat_level = self.threatTable[threatName]
        results = self.database.execute_query(f"SELECT * FROM hybrid_idps.innerLayer WHERE event_type = '{event_type}'")
        results = self.extract_payload(results)

        for payload, all_events in results.items():
            for event in all_events:
                payload_dict = json.loads(payload)
                like_increment = payload_dict.get('likeIncrement')
                if like_increment > 1:
                    logName = f"{threatName}-{event['timestamp']}"
                    self.add_threat(logName, threatName,  event['username'], event['target_username'], event['ip_address'], event['geolocation'], event['timestamp'],
                                    threatName, threat_level, event['payload'])
                elif like_increment < -1:
                    logName = f"{threatName}-{event['timestamp']}"
                    self.add_threat(logName, threatName,  event['username'], event['target_username'], event['ip_address'], event['geolocation'], event['timestamp'],
                                    threatName, threat_level, event['payload'])

    def check_like_mismatch(self):

        event_type = 'likePost'
        threatName = "jsonComprimised"
        threat_level = self.threatTable[threatName]

        from datetime import datetime

        current_time = datetime.now()
        formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S') 

        postListEntries = self.database.execute_query(f"SELECT payload FROM hybrid_idps.innerLayer WHERE event_type = 'addPost'")
        post_ID_List = [postID[0] for postID in self.parse_payload(postListEntries)]
        
        likePostEntries = self.database.execute_query(f"SELECT payload FROM hybrid_idps.innerLayer WHERE event_type = 'likePost'")
        liked_post_ID_List = [postID[1:3] for postID in self.parse_payload(likePostEntries)]

        # results = self.database.execute_query(f"SELECT payload FROM hybrid_idps.innerLayer WHERE event_type = '{event_type}'")
        # sql_posts_likes = self.parse_and_sum_payload(results)
        with open('registeredUsers.json', 'r') as f:
            json_data = json.load(f)

        sql_post_likes_sum = {}
        json_posts_likes = {}
        
        for post_id in post_ID_List:
            likeIncrements = [val[1] for val in liked_post_ID_List if val[0] == post_id]
            print(f"LikeIncrements {likeIncrements} for post_id {post_id}")
            sql_post_likes_sum[post_id] = sum(likeIncrements) 

        for user in json_data:
            user_dict = user[1]
            posts = user_dict['posts']
            for post in posts:

                current_likes = post['likes']
                current_post_id = post['postID']
                
                json_posts_likes[current_post_id] = current_likes
                
                
                # this if condition may need to be changed
                if json_posts_likes != sql_post_likes_sum:
                    print(f"mismatch at {current_post_id}")
                    # logName = f"{threatName}-{results.event['timestamp']}"
                    self.add_threat(current_post_id, threatName, user[0], None, None, formatted_time, None,
                                     threatName, threat_level, current_post_id)
                    
                else:
                    print("likes match")

   
    def parse_and_sum_payload(self, results):
        data =  [list(json.loads(result['payload']).values())[1:] for result in results]
        result_dict = {}
        for entry in data:
            id, value = entry  
            if id in result_dict:
                result_dict[id] += value
            else:
                result_dict[id] = value

        return result_dict

  # Outputs {'br3f2jgjy': 1, 'l4rn8eaw7': 0}      




        
        
    def display_Events_and_calc_threat_level(self):
        for username, deviceData in self.devices.items():
            print("\n")
            print(f"username: {username}")
            logs = deviceData["logs"]
            threatLevel = 0
            for threatName, threadType in logs.items():
                print(f"        {threatName}")
                threatLevel += self.threatTable[threadType]
                
            if threatLevel > 1: threatLevel = 1
            self.set_threat_level(username, threatLevel)
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
    
    def extract_geo(self, results):
        geo_dict = {}
        for entry in results:
            geo = entry['geolocation']
            if geo not in geo_dict:
                geo_dict[geo] = []
            geo_dict[geo].append(entry)
        return geo_dict
    
    def extract_user(self, results):
        user_dict = {}
        for entry in results:
            user = entry['username']
            if user not in user_dict:
                user_dict[user] = []
            user_dict[user].append(entry)
        return user_dict

    def extract_payload(self, results):
        payload_dict = {}
        for entry in results:
            payload = entry['payload']
            if payload not in payload_dict:
                payload_dict[payload] = []
            payload_dict[payload].append(entry)
        return payload_dict
    
    def parse_payload(self, results):
        return [list(json.loads(result['payload']).values()) for result in results]
 
    def otherstuff(data):
        result_dict = {}
        for entry in data:
            id, value = entry  
            if id in result_dict:
                result_dict[id] += value
            else:
                result_dict[id] = value

        return result_dict

    def add_devices(self):
        results = self.database.execute_query(f"SELECT DISTINCT username from hybrid_idps.innerLayer")
        usernameList = [result['username'] for result in results] #Possibly IPV6
        
        for username in usernameList:
            # if ip.startswith("::ffff:"):     # ip_address ::ffff:192.168.1.99
            #     ip = ip.split(":")[-1]       # ip_address 192.168.1.99
            if username not in self.devices:
                self.devices[username] = {'threatLevel': 0, 'logs': {}}   
        
    def add_threat(self, logName, threatName, username, target_username, ip_address, geolocation, timestamp, event_type, threat_level, payload):
        
        if ip_address and ip_address.startswith("::ffff:"):     # ip_address ::ffff:192.168.1.99
            ip_address = ip_address.split(":")[-1] # ip_address 192.168.1.99
        
        if username in self.devices:
            print("entered second if")
            device = self.devices[username]
            threatLevel = self.threatTable[threatName]
            
            if logName not in device['logs']:
                
                device = self.devices[username]
                device['logs'][logName] = threatName
        self.database.add_threat_to_inner_Layer_Threats_DB(username, target_username, ip_address, geolocation, timestamp, event_type, threat_level, payload)
        # else:
            # print(f"Failed to add_threat. Device with IP address {ip_address} does not exist.")
            
    def set_threat_level(self, username, newThreatLevel):
        if username in self.devices:
            device = self.devices[username]['threatLevel'] = newThreatLevel
        else:
            print(f"Failed to set_threat_level. Device with username {username} does not exist.")

if __name__ == "__main__":
    x = InnerLayer()
