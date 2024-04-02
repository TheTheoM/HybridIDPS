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
}

class InnerLayerEvents {
  constructor() {
    this.threatThreshold = 0
    this.mySqlConnection = new MySQLConnection();
    this.mySqlConnection.connect();
  }

  setThreatThreshold(threatThreshold) {
    this.threatThreshold = threatThreshold 
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
    // addEvent(username, ip_address, geolocation, event_type, payload = null, timestamp = null) //TODO Add logging for connecting to server

      let device_ip_address = req.connection.remoteAddress;

      let geolocation       = "Sydney AU"   //We will implement a custom routing table, so we don't have to actuall vpn to differnet locations to simulate this
                                            // For example 192.168.1.0 - 192.168.1.10 will be sydney then .10 to .20 will be London for example.  This will not change the 
                                            // validity of the system, as this is not a test of geolocation accuracy but behavioral. 
      let device_Username = null;

      socket.send(JSON.stringify({ message: 'Are you registered?', action: 'checkRegistration' }));
      socket.on('message', (message) => {
        const data = JSON.parse(message);
        
        switch(data.action) {
          case 'register':
            if (this.isUserRegistered(data.username)) {
              // User is already registered
              socket.send(JSON.stringify({ message: 'User is already registered', action: 'registrationSuccess' }));
              this.innerLayer.addEvent(data.username, null,  device_ip_address, geolocation, 'alreadyRegistered', null, null)
          } else {            // Register the user

            this.registerUser(data.username, data.password, data.email);
            this.innerLayer.addEvent(data.username, null,  device_ip_address, geolocation, 'registrationSuccess', null, null)
            socket.send(JSON.stringify({ message: 'Registration successful!', action: 'registrationSuccess' }));
          }
          break;
        
        case 'login':
          if (this.isUserValid(data.username, data.password)) {
            socket.send(JSON.stringify({ message: 'Permission granted to access viewFeed and viewUser', action: 'viewFeedAndUser' }));
            this.innerLayer.addEvent(data.username, null,  device_ip_address, geolocation, 'successfulLogin', null, null)
            this.innerLayer.addEvent(data.username, null,  device_ip_address, geolocation, 'viewFeedAndUser', null, null)
            device_Username = data.username;

          } else {
            socket.send(JSON.stringify({ message: 'Invalid credentials', action: 'invalidCredentials' }));
            this.innerLayer.addEvent(data.username, null,  device_ip_address, geolocation, 'invalidCredentials', null, null)
          }
          break;
      
        case 'getUserByUsername':
          let userData = this.getUserByUsername(data.username);
          var target_username = data.username;
          if (userData) {
            socket.send(JSON.stringify({ user: userData, action: 'userDataByUsername'}));
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'userDataByUsername', null, null)

          } else {
            socket.send(JSON.stringify({ message: "Username doesn't exist.", action: 'invalidUsername'}));
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'invalidUsername', null, null)

          }
          break;

        case 'searchUsers':
            socket.send(JSON.stringify({ users:  this.getSearchedUsers(data.search), action: 'userList'}));
            var target_username = data.search;
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'userList', null, null)
            break;

        case 'searchPosts':
            socket.send(JSON.stringify({ posts:  this.getSearchedPosts(data.search), action: 'searchPosts'}));
            let payload = data.search;
            // If is sql injection or sum action search post threatLevel 10
            
            this.innerLayer.addEvent(device_Username, null,  device_ip_address, geolocation, 'searchPosts', null, payload)

            break;
        case 'addPost':
            this.addPost(device_Username, data.postTitle, data.content, data.keyWords, data.imageUrl, data.timestamp, data.likes, data.comments) 
            break;
        case "likePost":
          var {isSuccessful, target_username} = this.likePost(data.postID, data.increment)
          if (isSuccessful) {
            socket.send(JSON.stringify({ posts:  this.getPostList(20), action: 'likePost'}));
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'likePost', null, 
                JSON.stringify({'isSuccessful': true, 'postID': data.postID, 'likeIncrement': data.increment}))
          } else {
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'likePost',
                                     null, JSON.stringify({'isSuccessful': false, 'postID': data.postID, 'likeIncrement': data.increment}))
          }

        case 'getPostList':
          socket.send(JSON.stringify({ posts:  this.getPostList(20), action: 'postList'}));
          this.innerLayer.addEvent(device_Username, null,  device_ip_address, geolocation, 'getPostList', null, null)

          break;
        case 'addComment':
          var {isSuccessful, target_username} = this.addComment(data.postID, data.username,  data.comment)

          if (isSuccessful) {
            socket.send(JSON.stringify({ posts:  this.getPostList(20000), action: 'postList'}));
            this.innerLayer.addEvent(device_Username, null,  device_ip_address, geolocation, 'getPostList', 0, null, null)

            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'addComment', null, 
                                    JSON.stringify({'isSuccessful': true, 'postID': data.postID, 'comment': data.comment}))
          } else {
            console.log("Failed to add Comment.")
            this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'addComment', null, 
                                    JSON.stringify({'isSuccessful': false, 'postID': data.postID, 'comment': data.comment}))
          }
          break;

        case 'reportUserByUsername':
          // this.reportUser(data.username)
          var target_username = data.username;
          this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'reportUserByUsername', null, null)

          break;
        case 'friendUserByUsername':
          // this.friendUser(data.username)
          var target_username = data.username;

          this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'friendUserByUsername', null, null)

          break;
        case 'messageUserByUsername':
          var target_username = data.username;
          this.innerLayer.addEvent(device_Username, target_username,  device_ip_address, geolocation, 'messageUserByUsername', null, null)
          break;
        default:
          // This would be where failed api-manipulation attacks may occur. Will need to think about this more, on how to chuck all at info in the sql and analysis it 
          /// it on the otherend.
          this.innerLayer.addEvent(device_Username, null,  device_ip_address, geolocation, 'invalidAction', null, null)
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
