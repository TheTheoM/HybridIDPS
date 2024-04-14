import React, { useState, useEffect, useRef } from 'react';
import logo from './logo.svg';
import './App.css';

function LoginPage({webSocket, isConnected, isRegistered, username, setUsername,  password, setPassword,  email, setEmail, invalidPassword, isUsernameBanned}) {
  const handleUsernameChange = (event) => {
    setUsername(event.target.value);
  };
 
  const handlePasswordChange = (event) => {
    setPassword(event.target.value);
  };

  const handleEmailChange = (event) => {
    setEmail(event.target.value);
  };

  const handleLogIn = (event) => {
    const loginData = {
      action: 'login',
      username: username,
      password: password,
    };
    webSocket.current.send(JSON.stringify(loginData));
  }

  const handleRegistration = () => {
    const credentials = { username: username, password: password, email: email };
    localStorage.setItem('credentials', JSON.stringify(credentials));
    const registrationData = {
      action: 'register',
      username: username,
      password: password,
      email:    email,
    };
    webSocket.current.send(JSON.stringify(registrationData));
  };

  return (
    <>
      {!isConnected ? (
        <div className='container'>
          <div className='failedToConnect'>
            <h1>Failed To Connect to Server. </h1>
            <h3>Ensure 'instaKilo.js' is running:</h3>
            <code>cd innerLayer</code>
            <br></br>
            <code>node instaKilo.js</code>
            <h3> If it is running, ensure you have created the .env file</h3>
            <h3> If it it fails to run, ensure you have installed the required packages:</h3>
            <code>cd innerLayer</code>
            <br></br>
            <code>npm install .</code>
          </div>
        </div> 
      ) : isRegistered ? (
        <div className='container'>
          <div className= {!invalidPassword ? 'register_and_logIn': 'register_and_logIn wrongCreds' } style={{border: invalidPassword ? '2px solid rgb(243, 105, 90)' : '2px solid gray'}}>
            <input type="text" placeholder="Username" value={username} onChange={handleUsernameChange} />
            <input type="password" placeholder="Password" value={password} onChange={handlePasswordChange}
                  onKeyDown={(e) => { if (e.key === "Enter") {handleLogIn()}}}/>
            <button onClick={handleLogIn}>Log In</button>
        
            {/* {invalidPassword ? <h3 style={{color: 'red'}}>Invalid Username or Password</h3> : ""} */}
          </div>
        </div>
      ) : (
        <div className='container'> 
          <div className='register_and_logIn' style={{ border: isUsernameBanned ? '2px solid red' : '2px solid gray' }}>
          <input type="text" placeholder="Username" value={username} onChange={handleUsernameChange} />
          <input type="password" placeholder="Password" value={password} onChange={handlePasswordChange} 
                 />
          <input type="email" placeholder="Email" value={email} onChange={handleEmailChange} 
          onKeyDown={(e)=>{if (e.key === "Enter") {handleRegistration()}}}/>
          <button onClick={handleRegistration}>Register</button>

          {isUsernameBanned ? <p style={{'color': 'red'}}> Username Banned </p> : ""}

          
          </div>
        </div>
      )}
    </>
  );
}

export default LoginPage;