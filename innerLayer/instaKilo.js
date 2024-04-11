const WebSocket = require('ws');
const fs        = require('fs');
const mysql     = require('mysql2');
const geoip     = require('geoip-lite');
const axios     = require('axios');

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

  addDataToInnerLayer(username, target_username, ip_address, geolocation, timestamp, event_type, payload) {
    const sqlQuery = "INSERT INTO innerLayer (username, target_username,  ip_address, geolocation, timestamp, event_type, payload) VALUES (?, ?, ?, ?, ?, ?, ?)";
    const data = [username, target_username, ip_address, geolocation, timestamp, event_type, payload];
    
    this.connection.query(sqlQuery, data, (error, results, fields) => {
      if (error) {
        console.error('Error executing query: ' + error.stack);
        return;
      }
      // console.log('Data added to innerLayer successfully.');
    });
  }
  
  addDataToInnerLayerBulk(dataArray) {
    const sqlQuery = "INSERT INTO innerLayer (username, target_username, ip_address, geolocation, timestamp, event_type, payload) VALUES (?, ?, ?, ?, ?, ?, ?)";
    const values = dataArray.map(data => [data.username, data.target_username,  data.ip_address, data.geolocation, data.timestamp, data.event_type, data.payload]);
    
    this.connection.query(sqlQuery, [values], (error, results, fields) => {
      if (error) {
        console.error('Error executing query: ' + error.stack);
        return false;
      }
      console.log('Bulk data added to innerLayer successfully.');
    });
  }

  get_banned_usernames(banThreshold) {
    return new Promise((resolve, reject) => {
      const sqlQuery = "SELECT username, threat_level FROM hybrid_idps.innerLayerThreats ORDER BY timestamp DESC";
      const threatLevelsByUsername = {};
      const bannedUsernames = [];
    
      this.connection.query(sqlQuery, (error, results, fields) => {
        if (error) {
          console.error('Error at get_banned_usernames: ' + error.stack);
          reject(error);
          return;
        }
    
        results.forEach(result => {
          const username = result.username;
          const threatLevel = result.threat_level;
          if (!threatLevelsByUsername[username]) {
            threatLevelsByUsername[username] = 0;
          }
          threatLevelsByUsername[username] += threatLevel;
        });
    
        console.log('Accumulated Threat Levels by Username:', threatLevelsByUsername);
    
        for (const username in threatLevelsByUsername) {
          if (threatLevelsByUsername[username] > banThreshold) {
            bannedUsernames.push(username);
          }
        }
    
        resolve(bannedUsernames);
      });
    });
  }

}

class WebSocketServer {
  constructor(port) {
    this.port   = port;
    this.mySqlConnection = new MySQLConnection();
    this.mySqlConnection.connect();
    this.registeredUsers = new Map();
    this.bannedUsers = []
    this.banThreshold = 0.8
    this.server = new WebSocket.Server({ port });
    this.ban_daemon() //Activate the ban Daemon <:)
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

  ban_daemon() {
    setInterval(() => {
      this.mySqlConnection.get_banned_usernames(this.banThreshold).then(bannedUsernames => {
        console.log('Ban List:', bannedUsernames);
        this.bannedUsers = bannedUsernames
      }).catch(error => {
        console.error('Error fetching banned usernames:', error);
      });
    }, 1000)
  }

  saveRegisteredUsersToFile() {
    fs.writeFileSync('registeredUsers.json', JSON.stringify([...this.registeredUsers], null, 2), 'utf-8');
    }
  
  handleConnection(socket, req) {
    let device_ip_address = req.connection.remoteAddress;

    if (device_ip_address.includes(':')) {
      const ipv4Part = device_ip_address.split(':').pop();
      const ipv4 = ipv4Part.includes('::ffff:') ? ipv4Part.replace('::ffff:', '') : ipv4Part;
      device_ip_address = ipv4;
    }
    
    let geolocation = this.findLocation(device_ip_address)   //We will implement a custom routing table, so we don't have to actual vpn to different locations to simulate this
                                          // For example 192.168.1.0 - 192.168.1.10 will be sydney then .10 to .20 will be London for example.  This will not change the 
                                          // validity of the system, as this is not a test of geolocation accuracy but behavioral. 
    let device_Username = null;
    this.addEvent(null, null, device_ip_address, geolocation, "connectedToServer", null, null) // Connected to Server

    socket.send(JSON.stringify({ message: 'Are you registered?', action: 'checkRegistration' }));
    socket.on('message', (message) => {
      const data = JSON.parse(message);

      if (this.bannedUsers.includes(device_Username)) {
        console.log(`Disconnected banned user ${device_Username}`)
        socket.send(JSON.stringify({ message: 'You are permanency banned.', action: 'banned' }));
        socket.terminate()
      } 

      switch(data.action) {
        case 'register':
          if (this.bannedUsers.includes(data.username)) {
            // console.log(`Disconnected banned user ${data.username}`)
            socket.send(JSON.stringify({ message: 'Unavailable Username', action: 'usernameTaken' }));
          } else {
            if (this.isUserRegistered(data.username)) { // User is already registered
              socket.send(JSON.stringify({ message: 'User is already registered', action: 'registrationSuccess' }));
              this.addEvent(data.username, null,  device_ip_address, geolocation, 'alreadyRegistered', null, null)
            } else {            // Register the user
              this.registerUser(data.username, data.password, data.email);
              this.addEvent(data.username, null,  device_ip_address, geolocation, 'registrationSuccess', null, null)
              socket.send(JSON.stringify({ message: 'Registration successful!', action: 'registrationSuccess' }));
            }
          }
          break;
        
        case 'login':
          if (this.isUserValid(data.username, data.password)) {
            socket.send(JSON.stringify({ message: 'Permission granted to access viewFeed and viewUser', action: 'viewFeedAndUser' }));
            this.addEvent(data.username, null,  device_ip_address, geolocation, 'successfulLogin', null, null)
            this.addEvent(data.username, null,  device_ip_address, geolocation, 'viewFeedAndUser', null, null)
            device_Username = data.username;

          } else {
            socket.send(JSON.stringify({ message: 'Invalid credentials', action: 'invalidCredentials' }));
            this.addEvent(data.username, null,  device_ip_address, geolocation, 'invalidCredentials', null, null)
          }
          
          break;
      
        case 'getUserByUsername':
          let userData = this.getUserByUsername(data.username);
          var target_username = data.username;
          if (userData) {
            socket.send(JSON.stringify({ user: userData, action: 'userDataByUsername'}));
            this.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'userDataByUsername', null, null)

          } else {
            socket.send(JSON.stringify({ message: "Username doesn't exist.", action: 'invalidUsername'}));
            this.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'invalidUsername', null, null)

          }
          break;

        case 'searchUsers':
            socket.send(JSON.stringify({ users:  this.getSearchedUsers(data.search), action: 'userList'}));
            var target_username = data.search;
            this.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'userList', null, null)
            break;

        case 'searchPosts':
            socket.send(JSON.stringify({ posts:  this.getSearchedPosts(data.search), action: 'searchPosts'}));
            let payload = data.search;
            // If is sql injection or sum action search post threatLevel 10
            
            this.addEvent(device_Username, null,  device_ip_address, geolocation, 'searchPosts', null, payload)

            break;
        case 'addPost':
            this.addPost(device_Username, data.postTitle, data.content, data.keyWords, data.imageUrl, data.timestamp, data.likes, data.comments) 
            break;
        case "likePost":
          var {isSuccessful, target_username} = this.likePost(data.postID, data.increment)
          if (isSuccessful) {
            socket.send(JSON.stringify({ posts:  this.getPostList(20), action: 'likePost'}));
            this.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'likePost', null, 
                JSON.stringify({'isSuccessful': true, 'postID': data.postID, 'likeIncrement': data.increment}))
          } else {
            this.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'likePost',
                                    null, JSON.stringify({'isSuccessful': false, 'postID': data.postID, 'likeIncrement': data.increment}))
          }

        case 'getPostList':
          socket.send(JSON.stringify({ posts:  this.getPostList(20), action: 'postList'}));
          this.addEvent(device_Username, null,  device_ip_address, geolocation, 'getPostList', null, null)
          break;

        case 'addComment':
          var {isSuccessful, target_username} = this.addComment(data.postID, data.username,  data.comment)

          if (isSuccessful) {
            socket.send(JSON.stringify({ posts:  this.getPostList(20000), action: 'postList'}));
            this.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'addComment', null, 
                                    JSON.stringify({'isSuccessful': true, 'postID': data.postID, 'comment': data.comment}))
          } else {
            console.log("Failed to add Comment.")
            this.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'addComment', null, 
                                    JSON.stringify({'isSuccessful': false, 'postID': data.postID, 'comment': data.comment}))
          }
          break;

        case 'reportUserByUsername':
          // this.reportUser(data.username)
          var target_username = data.username;
          this.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'reportUserByUsername', null, null)

          break;
        case 'friendUserByUsername':
          // this.friendUser(data.username)
          var target_username = data.username;

          this.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'friendUserByUsername', null, null)

          break;
        case 'messageUserByUsername':
          var target_username = data.username;
          this.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'messageUserByUsername', null, null)
          break;
        default:
          // This would be where failed api-manipulation attacks may occur. Will need to think about this more, on how to chuck all at info in the sql and analysis it 
          /// it on the otherend.
          this.addEvent(device_Username, null,  device_ip_address, geolocation, 'invalidAction', null, null)
          socket.send(JSON.stringify({ message: 'Invalid action', action: 'invalidAction' }));
          break;
      }
    });
  }

  findLocation(ip) {
    if (ip.includes(':')) {
        const ipv4Part = ip.split(':').pop();
        const ipv4 = ipv4Part.includes('::ffff:') ? ipv4Part.replace('::ffff:', '') : ipv4Part;
        ip = ipv4;
    }
    const ip_ranges = {
        "0-42":    "Australia",
        "43-85":   "New Zealand",
        "86-128":  "Minsk",
        "129-171": "Prague",
        "172-214": "Finland",
        "215-255": "Mars",
    };
    const ipInt = parseInt(ip.split('.').pop(), 10);
  
    for (const [ipRange, location] of Object.entries(ip_ranges)) {
        const [startIp, endIp] = ipRange.split('-');
        const startIpInt = parseInt(startIp.split('.').pop(), 10);
        const endIpInt = parseInt(endIp.split('.').pop(), 10);
        if (startIpInt <= ipInt && ipInt <= endIpInt) {
            return location;
        }
    }
    return "Unknown Location";
  }
  
  addEvent(username, target_username, ip_address, geolocation, event_type,  timestamp = null, payload = null) {
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
      'payload': payload,                 // Optional payload data associated with the event
      'timestamp': timestamp              // Timestamp of the event
    };
    console.log(`Event Added: IP Address: ${log.ip_address} Event Type: ${log.event_type} `);
    console.log(`   Log: ${JSON.stringify(log)} \n`);
    this.mySqlConnection.addDataToInnerLayer(username, target_username, ip_address, geolocation, timestamp, event_type, payload)
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

const wss = new WebSocketServer(8100);

process.on('exit', () => {
  wss.saveRegisteredUsersToFile();
});

