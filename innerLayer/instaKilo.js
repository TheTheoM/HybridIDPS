const WebSocket = require('ws');
const fs        = require('fs');
const mysql     = require('mysql2');
const geoip     = require('geoip-lite');
const axios = require('axios');

class MySQLConnection {
  constructor(host = 'localhost', user = 'Hybrid_IDPS', password = 'css2', database = 'hybrid_idps') {
    this.host = host;
    this.user = user;
    this.password = password;
    this.database = database;
    this.connection = null;

  }

  connect() {
    this.connection = mysql.createConnection({
      host: this.host,
      user: this.user,
      password: this.password,
      database: this.database
    });

    this.connection.connect(err => {
      if (err) {
        console.error('Error connecting to MySQL database: ' + err.stack);
        return;
      }
      console.log('Connected to MySQL database as id ' + this.connection.threadId);
    });
  }

  executeQuery(sqlQuery, callback) {
    this.connection.query(sqlQuery, (error, results, fields) => {
      if (error) {
        console.error('Error executing query: ' + error.stack);
        callback(error, null, null);
        return;
      }
      callback(null, results, fields);
    });
  }

  disconnect() {
    this.connection.end(err => {
      if (err) {
        console.error('Error closing MySQL database connection: ' + err.stack);
        return;
      }
      console.log('MySQL database connection closed.');
    });
  }

  addDataToInnerLayer(username, target_username, ip_address, geolocation, timestamp, event_type, threat_level, payload) {
    const sqlQuery = "INSERT INTO innerLayer (username, target_username,  ip_address, geolocation, timestamp, event_type, threat_level, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    const data = [username, target_username, ip_address, geolocation, timestamp, event_type, threat_level, payload];
    
    this.connection.query(sqlQuery, data, (error, results, fields) => {
      if (error) {
        console.error('Error executing query: ' + error.stack);
        return;
      }
      // console.log('Data added to innerLayer successfully.');
    });
  }
  
  addDataToInnerLayerBulk(dataArray) {
    
    const sqlQuery = "INSERT INTO innerLayer (username, target_username, ip_address, geolocation, timestamp, event_type, threat_level, payload) VALUES (?, ?,  ?, ?, ?, ?, ?, ?)";
    const values = dataArray.map(data => [data.username, data.target_username,  data.ip_address, data.geolocation, data.timestamp, data.event_type, data.threat_level, data.payload]);
    
    this.connection.query(sqlQuery, [values], (error, results, fields) => {
      if (error) {
        console.error('Error executing query: ' + error.stack);
        return false;
      }
      console.log('Bulk data added to innerLayer successfully.');
    });
  }
}

class InnerLayerEvents {
  constructor() {
    this.threatThreshold = 0
    this.eventLogs = new Map();
    this.mySqlConnection = new MySQLConnection();
    this.mySqlConnection.connect();
  }

  setThreatThreshold(threatThreshold) {
    this.threatThreshold = threatThreshold 
  }

  addEvent(username, target_username, ip_address, geolocation, event_type, threat_level,  timestamp = null, payload = null) {
    if (timestamp == null) {
      let currentISOTime = new Date().toISOString()
      timestamp = currentISOTime.replace('T', ' ').replace(/\.\d+Z$/, '');
   }
    let log = {
      'username': username,               // Username of the user triggering the event
      'target_username': target_username, // Username of the user the event is triggered against. report(target_username) etc
      'ip_address': ip_address,           // IP address associated with the event
      'geolocation': geolocation,         // Geolocation information of the event
      'event_type': event_type,           // Type of event triggered
      'threat_level': threat_level,       // Threat level associated with the event
      'payload': payload,                 // Optional payload data associated with the event
      'timestamp': timestamp              // Timestamp of the event
    };


    let events_by_ip = this.eventLogs.get(ip_address);


    if (events_by_ip) {
      this.eventLogs.set(ip_address, {    
        "threatInfo": {
          "threatLevel": events_by_ip.threatInfo.threatLevel, 
          "threatEvents": new Map(events_by_ip.threatInfo.threatEvents),
        },
        "logs": [...events_by_ip.logs , log],
      })

    } else {
      this.eventLogs.set(ip_address, {
          "threatInfo": {
            "threatLevel": 0, 
            "threatEvents": new Map(),
          },
          "logs": [log],
        });
    }

    console.log(`Event Added: ${JSON.stringify(log)}`);
    // let dataArray = [username, ip_address, geolocation, timestamp, event_type, threat_level, payload]
    this.mySqlConnection.addDataToInnerLayer(username, target_username, ip_address, geolocation, timestamp, event_type, threat_level, payload)

    this.runOnEventsUpdate();
    
  }

  runOnEventsUpdate() {
    let bruteForceThreats = this.FindBruteForce("invalidCredentials")
      for (const [ipAddress, logEntry] of this.eventLogs.entries()) {
        let threatLevel = 0;

        if (!logEntry || !logEntry.threatInfo) {
            continue;
        }

        const { _, threatEvents } = logEntry.threatInfo;

        if (threatEvents.size <= 0 || threatLevel < 0) {
          continue
        }
        for (const [event, threatIncrement] of threatEvents) {
          
          threatLevel += threatIncrement
          
          if (threatLevel >= 1 ) {
            threatLevel = 1
          }
          
        }

        let ansiColor = "\x1b[33m"

        if (threatLevel >= 0.5) {
            ansiColor =  "\x1b[31m"; // Red color
        }

        console.log(ansiColor + `Threat events for IP address ${ipAddress} @ threat level ${threatLevel}:` + '\x1b[0m');

        for (const [event, threatIncrement] of threatEvents) {
          console.log(ansiColor + `    ${event}    ${threatIncrement}` + '\x1b[0m');
        }
  
      }
  }

  FindBruteForce(event_type) {
    let countThreshold = 2
    let threatIncrement = 0.3

    const events = {};
    for (const [ip, eventInfo] of this.eventLogs.entries()) {
      let logs = eventInfo.logs;
      const bruteForceEvents = logs.filter(log => log.event_type === event_type);
      events[ip] = bruteForceEvents;
    }
  
    let count = 0;
    Object.entries(events).forEach(([ip, events]) => {
      for (const event of events) {
        count++;
        if (count > countThreshold) { 
          // let keyName = `[${ip}]:    ${event_type}    ${event.timestamp}`;
          let keyName = `${event_type}    ${event.timestamp} `;
          this.eventLogs.get(ip).threatInfo.threatEvents.set(keyName, threatIncrement)
          count = 0;
        }
      }
    })

  
  }
  
}

class WebSocketServer {
  constructor(port, events) {
    this.port   = port;
    this.innerLayer = events;
    this.registeredUsers = new Map();
    this.server = new WebSocket.Server({ port });
    if (fs.existsSync('registeredUsers.json')) {
      const data = fs.readFileSync('registeredUsers.json', 'utf8');
      this.registeredUsers = new Map(JSON.parse(data));
    } else {
      fs.writeFileSync('registeredUsers.json', JSON.stringify({}));
    }
    this.server.on('connection', (socket, req) => {
      this.handleConnection(socket, req);
    });
    console.log(`WebSocket server is running on port ${port}`);
  }

  saveRegisteredUsersToFile() {
    fs.writeFileSync('registeredUsers.json', JSON.stringify([...this.registeredUsers], null, 2), 'utf-8');
    }
  
  handleConnection(socket, req) {
    // addEvent(username, ip_address, geolocation, event_type, threat_level, payload = null, timestamp = null) {

      let device_ip_address = req.connection.remoteAddress;

      let geolocation       = "Sydney AU"   //We will implement a custom routing table, so we don't have to actuall vpn to differnet locations to simulate this
                                            // For example 192.168.1.0 - 192.168.1.10 will be sydney then .10 to .20 will be London for example.  This will not change the 
                                            // validity of the system, as this is not a test of geolocation accuracy but behavioral. 
      let threat_level      = 0;

      let device_Username = null;

      socket.send(JSON.stringify({ message: 'Are you registered?', action: 'checkRegistration' }));
      socket.on('message', (message) => {
        const data = JSON.parse(message);
        
        switch(data.action) {
          case 'register':
            if (this.isUserRegistered(data.username)) {
              // User is already registered
              socket.send(JSON.stringify({ message: 'User is already registered', action: 'registrationSuccess' }));
              this.innerLayer.addEvent(data.username, null,  device_ip_address, geolocation, 'alreadyRegistered', threat_level, null, null)
          } else {            // Register the user

            this.registerUser(data.username, data.password, data.email);
            this.innerLayer.addEvent(data.username, null,  device_ip_address, geolocation, 'registrationSuccess', threat_level, null, null)
            socket.send(JSON.stringify({ message: 'Registration successful!', action: 'registrationSuccess' }));
          }
          break;
        
        case 'login':
          if (this.isUserValid(data.username, data.password)) {
            socket.send(JSON.stringify({ message: 'Permission granted to access viewFeed and viewUser', action: 'viewFeedAndUser' }));
            this.innerLayer.addEvent(data.username, null,  device_ip_address, geolocation, 'successfulLogin', threat_level, null, null)
            this.innerLayer.addEvent(data.username, null,  device_ip_address, geolocation, 'viewFeedAndUser', threat_level, null, null)
            device_Username = data.username;

          } else {
            socket.send(JSON.stringify({ message: 'Invalid credentials', action: 'invalidCredentials' }));
            this.innerLayer.addEvent(data.username, null,  device_ip_address, geolocation, 'invalidCredentials', threat_level, null, null)
          }
          break;
      
        case 'getUserByUsername':
          let userData = this.getUserByUsername(data.username);
          var target_username = data.username;
          if (userData) {
            socket.send(JSON.stringify({ user: userData, action: 'userDataByUsername'}));
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'userDataByUsername', threat_level, null, null)

          } else {
            socket.send(JSON.stringify({ message: "Username doesn't exist.", action: 'invalidUsername'}));
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'invalidUsername', threat_level, null, null)

          }
          break;

        case 'searchUsers':
            socket.send(JSON.stringify({ users:  this.getSearchedUsers(data.search), action: 'userList'}));
            var target_username = data.search;
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'userList', threat_level, null, null)
            break;

        case 'searchPosts':
            socket.send(JSON.stringify({ posts:  this.getSearchedPosts(data.search), action: 'searchPosts'}));
            let payload = data.search;
            // If is sql injection or sum action search post threatLevel 10
            
            this.innerLayer.addEvent(device_Username, null,  device_ip_address, geolocation, 'searchPosts', threat_level, null, payload)

            break;
        case 'addPost':
            this.addPost(device_Username, data.postTitle, data.content, data.keyWords, data.imageUrl, data.timestamp, data.likes, data.comments) 
            break;
        case "likePost":
          var {isSuccessful, target_username} = this.likePost(data.postID, data.increment)
          if (isSuccessful) {
            threat_level = 0
            socket.send(JSON.stringify({ posts:  this.getPostList(20), action: 'likePost'}));
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'likePost', threat_level, null, 
                JSON.stringify({'isSuccessful': true, 'postID': data.postID, 'likeIncrement': data.increment}))
          } else {
            threat_level = 5 // Change
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'likePost',
                                     threat_level, null, JSON.stringify({'isSuccessful': false, 'postID': data.postID, 'likeIncrement': data.increment}))
          }

        case 'getPostList':
          socket.send(JSON.stringify({ posts:  this.getPostList(20), action: 'postList'}));
          this.innerLayer.addEvent(device_Username, null,  device_ip_address, geolocation, 'getPostList', threat_level, null, null)

          break;
        case 'addComment':
          var {isSuccessful, target_username} = this.addComment(data.postID, data.username,  data.comment)

          if (isSuccessful) {
            socket.send(JSON.stringify({ posts:  this.getPostList(20000), action: 'postList'}));
            this.innerLayer.addEvent(device_Username, null,  device_ip_address, geolocation, 'getPostList', 0, null, null)

            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'addComment', threat_level, null, 
                                    JSON.stringify({'isSuccessful': true, 'postID': data.postID, 'comment': data.comment}))
          } else {
            console.log("Failed to add Comment.")
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'addComment', threat_level, null, 
                                    JSON.stringify({'isSuccessful': false, 'postID': data.postID, 'comment': data.comment}))
          }
          break;

        case 'reportUserByUsername':
          // this.reportUser(data.username)
          var target_username = data.username;
          this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'reportUserByUsername', threat_level, null, null)

          break;
        case 'friendUserByUsername':
          // this.friendUser(data.username)
          var target_username = data.username;

          this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'friendUserByUsername', threat_level, null, null)

          break;
        case 'messageUserByUsername':
          var target_username = data.username;
          this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'messageUserByUsername', threat_level, null, null)
          break;
        default:
          // This would be where failed api-manipulation attacks may occur. Will need to think about this more, on how to chuck all at info in the sql and analysis it 
          /// it on the otherend.
          this.innerLayer.addEvent(device_Username, null,  device_ip_address, geolocation, 'invalidAction', threat_level, null, null)
          socket.send(JSON.stringify({ message: 'Invalid action', action: 'invalidAction' }));
          break;
      }
    });
  }
  
  async privateToPublic(privateIp) {
    try {
        // Fetch public IP address using an external service
        const response = await axios.get('https://api.ipify.org?format=json');
        const publicIp = response.data.ip;
        
        return publicIp;
    } catch (error) {
        console.error('Error fetching public IP:', error);
        return null;
    }
  }

  isUserRegistered(username) {
    return this.registeredUsers.has(username)
  }

  isUserValid(username, password) {
    return (this.registeredUsers.has(username) && this.registeredUsers.get(username).password === password)
  }

  registerUser(username, password, email) {
    this.registeredUsers.set(username, {'password': password,
                                        'email':    email,
                                        'posts':  []})
    this.saveRegisteredUsersToFile()

  }

  addPost(username, postTitle, content, keyWords, imageUrl, timestamp, likes, comments) {
    if (!this.registeredUsers.has(username)) {
      console.log("User not found.");
      return false;
    }
    const user = this.registeredUsers.get(username);
    const postId = Math.random().toString(36).substr(2, 9);
    const post = {
      'id': postId,
      'username': username,
      'postTitle': postTitle,
      'content': content,
      'keyWords': keyWords,
      'imageUrl': imageUrl,
      'timestamp': timestamp,
      'likes': likes,
      'comments': comments
    };
    user.posts.push(post);
    this.saveRegisteredUsersToFile()
    return true
  }

  addComment(postID, username, comment) {
    // "increment + / -s"
    let post = this.getPostList(1000000).filter(user => user.id === postID)[0];
    if (post) {
      post.comments.push({"username": username, "comment": comment})
      this.saveRegisteredUsersToFile()
      return {
        isSuccessful: true,
        target_username: post.username 
      }
    } else {
      console.log(`PostID ${postID} not found.`)
      return {
        isSuccessful: false,
        target_username: null 
      }
    }
  }

  likePost(postID, increment) {
    // "increment + / -s"
    let post = this.getPostList(1000000).filter(user => user.id === postID)[0];
    if (post) {
        post.likes += parseInt(increment)
        this.saveRegisteredUsersToFile()
        return {
          isSuccessful: true,
          target_username: post.username 
        }

    } else {
      console.log(`PostID ${postID} not found.`)
      return {
        isSuccessful: false,
        target_username: null 
      }

    }
  }
  
  getPostList(maxEntries) {
    let allPosts = [];
    for (const [, user] of this.registeredUsers) {
      allPosts = allPosts.concat(user.posts);
    }
    allPosts.sort((a, b) => a.timestamp - b.timestamp);

    return allPosts.slice(0, maxEntries);
  }
  
  getSearchedPosts(searchTerm) {
    const matchingPosts = [];
    for (const [username, user] of this.registeredUsers.entries()) {
      for (const post of user.posts) {
        const postTitle = post.postTitle
        if (postTitle.toLowerCase().includes(searchTerm.toLowerCase())) {
          matchingPosts.push(post)
        }
      }
    }
    return matchingPosts;
  }

  
  getUserByUsername(username) {
    return this.registeredUsers.get(username);
  }
  
  getSearchedUsers(userSearchTerm) {
    const searchedUsers = {};
    const searchTermLower = userSearchTerm.toLowerCase();
    if (searchTermLower.trim() === '') {
        return searchedUsers;
    }
    for (const [username, user] of this.registeredUsers) {
        const usernameLower = username.toLowerCase();
        if (usernameLower.includes(searchTermLower)) {
            searchedUsers[username] = user;
        }
    }
    return searchedUsers;
  }
}

const events = new InnerLayerEvents()
const wss = new WebSocketServer(8100, events);

process.on('exit', () => {
  wss.saveRegisteredUsersToFile();
});
