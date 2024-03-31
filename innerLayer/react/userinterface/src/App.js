import React, { useState, useEffect, useRef } from 'react';
import logo from './logo.svg';
import './App.css';
import LoginPage from './LoginPage.js';
import InstaKiloClient from './InstaKiloClient/InstaKiloClient.js';
function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [isConnected, setIsConnected] = useState(false); 
  const [isRegistered, setIsRegistered] = useState(false); 
  const [isLoggedIn, setIsLoggedIn] = useState(0);
  const [invalidPassword, setInvalidPassword] = useState(0); 
  const [requestedUserData, setRequestedUserData] = useState({}); 
  const [searchedUserList, setSearchedUserList] = useState({}); 
  const [searchedPostList, setSearchedPostList] = useState({}); 
  const [postList, setPostList] = useState([])
  const webSocket = useRef(null);
  const ws_url = `ws://${process.env.REACT_APP_WEBSOCKET_SERVER_IP}`; 
  useEffect(() => {
    webSocket.current = new WebSocket(ws_url);

    webSocket.current.onopen = () => {
      console.log('WebSocket connection opened');
      setIsConnected(true);
    };

    webSocket.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log('Received message:', data);

      switch (data.action) {
        case 'checkRegistration':
          const storedCredentials = localStorage.getItem('credentials');
          if (storedCredentials) {
            const { username, password, email } = JSON.parse(storedCredentials);
            const registrationData = {
              action: 'register',
              username: username,
              password: password,
              email: email,
            };
            webSocket.current.send(JSON.stringify(registrationData));
          } else {
            setIsRegistered(false);
          }
          break;
      
        case 'registrationSuccess':
          setIsRegistered(true);
          break;
      
        case 'viewFeedAndUser':
          console.log("Logged In Successfully");
          setIsLoggedIn(true);
          setInvalidPassword(0)
          break;
      
        case 'invalidCredentials':
          console.log("Incorrect Username or Password");
          setIsLoggedIn(false);
          setInvalidPassword(1)
          break;
      
        case 'userList':
          setSearchedUserList(data.users)
          break;
        case 'searchPosts':
          setSearchedPostList(data.posts)
          break;
        case 'postList':
          setPostList(data.posts)
          break;
        default:
          // Handle default case if needed
      }
    };

    webSocket.current.onclose = () => {
      console.log('WebSocket connection closed');
      setIsConnected(false); 
    };

    return () => {
      webSocket.current.close();
    };
  }, []);

  return (
    <div className="App">
      {isLoggedIn ?
        <InstaKiloClient username = {username} webSocket = {webSocket} requestedUserData = {requestedUserData} searchedUserList = {searchedUserList} searchedPostList = {searchedPostList} postList = {postList}/>
      :
        <LoginPage webSocket = {webSocket} isConnected = {isConnected} isRegistered = {isRegistered} username = {username} setUsername = {setUsername}
                password = {password} setPassword = {setPassword} email = {email} setEmail = {setEmail} invalidPassword = {invalidPassword}/>
      }
    </div>
  );
}

export default App;
