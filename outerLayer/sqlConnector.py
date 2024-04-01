import mysql.connector

class MySQLConnection:
    def __init__(self, host='localhost', user='innerLayer', password='css2', database='hybrid_idps'):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.connection = None

    def connect(self):
        self.connection = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database
        )
        if self.connection.is_connected():
            print(f'Connected to MySQL database as id {self.connection.connection_id}')
        else:
            print('Failed to connect to MySQL database')

    def execute_query(self, sql_query, callback):
        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(sql_query)
        results = cursor.fetchall()
        cursor.close()
        callback(None, results)
        
    def add_data_to_outer_layer(self, ip_address, geolocation, event_type, threat_level, dateTime, source_port, destination_port, protocol, payload):
        # need to implement dateTime. Its probs different standards from node.js to python to sql. make all utc iso whatever
        sql_query = "INSERT INTO outerLayer (ip_address, geolocation, event_type, threat_level, source_port, destination_port, protocol, payload) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        cursor = self.connection.cursor()
        data = (ip_address, geolocation, event_type, threat_level, source_port, destination_port, protocol, payload)
        cursor.execute(sql_query, data)
        self.connection.commit()
        cursor.close()
        print('Data added to outerLayer successfully.')
        return True

    def add_data_to_outer_layer_bulk(self, data):
        try:
            sql_query = "INSERT INTO outerLayer (ip_address, geolocation, event_type, threat_level, timestamp) VALUES (%s, %s, %s, %s, %s)"
            cursor = self.connection.cursor()
            cursor.executemany(sql_query, data)
            self.connection.commit()
            cursor.close()
            print('Bulk data added to outerLayer successfully.')
            return True
        except Exception as e:
            print(f"Error adding bulk data to outerLayer: {e}")
            return False

    def disconnect(self):
        self.connection.close()
        print('MySQL database connection closed.')

if __name__ == "__main__":
    mySqlConnection = MySQLConnection()
    mySqlConnection.connect()
    mySqlConnection.add_data_to_outer_layer("192.168.1.100", "Londen, Australia", "Login", 0, None, None, None, None)
    mySqlConnection.execute_query('SELECT * from hybrid_idps.outerLayer', lambda error, results: print('The results are: ', results))
    mySqlConnection.disconnect()


        
            