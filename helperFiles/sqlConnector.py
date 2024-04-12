import mysql.connector

class MySQLConnection:
    def __init__(self, host='localhost', user='Hybrid_IDPS', password='css2', database='hybrid_idps'):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.verbose = True
        self.connection = None
        self.connect()

    def connect(self):
        self.connection = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database
        )
        if self.connection.is_connected():
            print(f'Connected to MySQL database as id {self.connection.connection_id}') if self.verbose else None
        else:
            print('Failed to connect to MySQL database')

    def execute_query(self, sql_query):
        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(sql_query)
        results = cursor.fetchall()
        cursor.close()
        return results
        
    def add_data_to_outer_layer(self, ip_address, geolocation, event_type, threat_level, dateTime, source_port, destination_port, protocol, payload):
        # need to implement dateTime. Its probs different standards from node.js to python to sql. make all utc iso whatever
        sql_query = "INSERT INTO outerLayer (ip_address, geolocation, event_type, threat_level, source_port, destination_port, protocol, payload) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        cursor = self.connection.cursor()
        data = (ip_address, geolocation, event_type, threat_level, source_port, destination_port, protocol, payload)
        cursor.execute(sql_query, data)
        self.connection.commit()
        cursor.close()
        print('Data added to outerLayer successfully.')  if self.verbose else None
        return True

    def add_data_to_outer_layer_bulk(self, data):
        try:
            sql_query = "INSERT INTO outerLayer (ip_address, geolocation, timestamp, event_type, threat_level, source_port, destination_port, protocol) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            cursor = self.connection.cursor()
            cursor.executemany(sql_query, data)
            self.connection.commit()
            cursor.close()
            print('Bulk data added to outerLayer successfully.')  if self.verbose else None
            return True
        except Exception as e:
            print(f"Error adding bulk data to outerLayer: {e}")
            return False

    def hazmat_wipe_Table(self, tableName):
        try:
            sql_query = f"DELETE FROM {tableName}"
            cursor = self.connection.cursor()
            cursor.execute(sql_query)
            row_count = cursor.rowcount
            self.connection.commit()
            cursor.close()
            print(f"{row_count} records deleted from table {tableName} successfully.")
            return True
        except Exception as e:
            print(f"Error deleting records from table {tableName}: {e}")
            return False
        
    def setVerbose(self, verboseState):
        self.verbose = verboseState
        
    def disconnect(self):
        self.connection.close()
        print('MySQL database connection closed.')  if self.verbose else None
        
    def add_threat_to_outer_Layer_Threats_DB(self, ip_address, logName, geolocation, timestamp, threatName, threatLevel):
        sql_query = "INSERT INTO outerLayerThreats (ip_address, logName, geolocation, timestamp, threatName, threat_level) VALUES (%s, %s, %s, %s, %s, %s)"
        cursor = self.connection.cursor()
        data = (ip_address, logName, geolocation, timestamp, threatName, threatLevel)
        cursor.execute(sql_query, data)
        self.connection.commit()
        cursor.close()
        print('Data added to outerLayerThreats successfully.')  if self.verbose else None
        return True
    
    def add_threat_to_inner_Layer_Threats_DB(self, username, target_username, ip_address, geolocation, timestamp, event_type, threat_level, payload):
        sql_query = "INSERT INTO innerLayerThreats (username, target_username, ip_address, geolocation, timestamp, event_type, threat_level, payload) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        cursor = self.connection.cursor()
        data = (username, target_username, ip_address, geolocation, timestamp, event_type, threat_level, payload)
        cursor.execute(sql_query, data)
        self.connection.commit()
        cursor.close()
        print('Data added to innerLayerThreats successfully.')  if self.verbose else None
        return True
    
    
    def get_inner_ips_by_username(self, usernames):
        usernameIPs = {}
        for username in usernames:
            sql_query = f"SELECT distinct ip_address FROM hybrid_idps.innerLayerThreats WHERE username = '{username}'"
            for result in self.execute_query(sql_query):
                for IP in result['ip_address']:
                    usernameIPs.setdefault(username, [])
                    usernameIPs[username].append(IP)
                    
        return usernameIPs
    
    def get_usernames_above_threshold(self, threat_Threshold):
        sql_query = "SELECT username, threat_level FROM hybrid_idps.innerLayerThreats ORDER BY timestamp DESC"

        username_threat_levels = {}
        
        for result in self.execute_query(sql_query):
            username, threat_level = result.values()
            username_threat_levels.setdefault(username, 0)
            username_threat_levels[username] += threat_level
                
        return [username for username, threat_level in username_threat_levels.items() if threat_level >= threat_Threshold]
                
    def get_banned_ips(self, ban_threshold, printUpdates = True):
        banned_ips = []
        results = self.execute_query("SELECT ip_address, threat_level FROM outerLayerThreats ORDER BY timestamp DESC")
        
        ip_threat_levels = {}
        for entry in results:
            ip_address = entry['ip_address']
            threat_level = entry['threat_level']
            if ip_address in ip_threat_levels:
                ip_threat_levels[ip_address] += threat_level
            else:
                ip_threat_levels[ip_address] = threat_level
        
        for ip_address, total_threat_level in ip_threat_levels.items():
            if total_threat_level >= ban_threshold and ip_address not in banned_ips:
                banned_ips.append(ip_address)
                if printUpdates:
                    print(f"IP: {ip_address}, Threat Level: {total_threat_level}, Ban Threshold: {ban_threshold}")
                    print(f"Added {ip_address} to the ban list.")

        return banned_ips

if __name__ == "__main__":
    mySqlConnection = MySQLConnection()
    mySqlConnection.disconnect()
    # mySqlConnection.add_data_to_outer_layer("192.168.1.100", "Londen, Australia", "Login", 0, None, None, None, None)
    # mySqlConnection.execute_query('SELECT * from hybrid_idps.outerLayer', lambda error, results: print('The results are: ', results))
