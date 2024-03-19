const WebSocket = require('ws');
const fs = require('fs');

class WebSocketServer {
  constructor(port) {
    this.port = port;
    this.registeredUsers = new Map();
    this.server = new WebSocket.Server({ port });

    if (fs.existsSync('registeredUsers.json')) {
      const data = fs.readFileSync('registeredUsers.json', 'utf8');
      this.registeredUsers = new Map(JSON.parse(data));
    } else {
      fs.writeFileSync('registeredUsers.json', JSON.stringify({}));
    }

    this.server.on('connection', (socket) => {
      this.handleConnection(socket);
    });

    console.log(`WebSocket server is running on port ${port}`);
  }

  saveRegisteredUsersToFile() {
    fs.writeFileSync('registeredUsers.json', JSON.stringify([...this.registeredUsers], null, 2), 'utf-8');
    }
  
  handleConnection(socket) {
    socket.send(JSON.stringify({ message: 'Are you registered?', action: 'checkRegistration' }));

    socket.on('message', (message) => {
      const data = JSON.parse(message);

      switch(data.action) {
        case 'register':
          if (this.isUserRegistered(data.username)) {
            // User is already registered
            socket.send(JSON.stringify({ message: 'User is already registered', action: 'registrationSuccess' }));
          } else {
            // Register the user
            this.registerUser(data.username, data.password, data.email);
            socket.send(JSON.stringify({ message: 'Registration successful!', action: 'registrationSuccess' }));
          }
          break;
        
        case 'login':
          if (this.isUserValid(data.username, data.password)) {
            socket.send(JSON.stringify({ message: 'Permission granted to access viewFeed and viewUser', action: 'viewFeedAndUser' }));
          } else {
            socket.send(JSON.stringify({ message: 'Invalid credentials', action: 'invalidCredentials' }));
          }
          break;
      
        case 'getUserByUsername':
          let userData = this.getUserByUsername(data.username);
          if (userData) {
            socket.send(JSON.stringify({ user: userData, action: 'userDataByUsername'}));
          } else {
            socket.send(JSON.stringify({ message: "Username doesn't exist.", action: 'invalidUsername'}));
          }
          break;
        case 'searchUsers':
            socket.send(JSON.stringify({ users:  this.getSearchedUsers(data.search), action: 'userList'}));
            break;
        case 'searchPosts':
            socket.send(JSON.stringify({ posts:  this.getSearchedPosts(data.search), action: 'searchPosts'}));
            break;
        case 'addPost':
            this.addPost(data.username, data.postTitle, data.content, data.keyWords, data.imageUrl, data.timestamp, data.likes, data.comments) 
            break;
        case "likePost":
          this.likePost(data.postID, data.increment)
          socket.send(JSON.stringify({ posts:  this.getPostList(20), action: 'postList'}));
        case 'getPostList':
          socket.send(JSON.stringify({ posts:  this.getPostList(20), action: 'postList'}));
          break;
        case 'addComment':
          this.addComment(data.postID, data.username,  data.comment)
          socket.send(JSON.stringify({ posts:  this.getPostList(20), action: 'postList'}));
          break;
        default:
          socket.send(JSON.stringify({ message: 'Invalid action', action: 'invalidAction' }));
          break;
      }
    });
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
        console.log(post)
        this.saveRegisteredUsersToFile()
    } else {
      console.log(`PostID ${postID} not found.`)
    }
  }

  likePost(postID, increment) {
    // "increment + / -s"
    let post = this.getPostList(1000000).filter(user => user.id === postID)[0];
    if (post) {
        post.likes += parseInt(increment)
        console.log(post)
        this.saveRegisteredUsersToFile()

    } else {
      console.log(`PostID ${postID} not found.`)
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
    console.log(searchTerm)
    const matchingPosts = [];
    for (const [username, user] of this.registeredUsers.entries()) {
      console.log(username)
      console.log(user)

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