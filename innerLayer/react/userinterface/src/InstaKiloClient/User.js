import React, { useEffect, useState } from 'react';
import Cross from './Cross';
import Add from './Add';

const User = ({ username, imageUrl, likes, comments, hideUser, webSocket }) => {
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    webSocket.current.send(JSON.stringify({
      action: 'getUserByUsername',
      username: username,
    }));
  }, []);

  const handleReport = () => {
    webSocket.current.send(JSON.stringify({
      action: 'reportUserByUsername',
      username: username,
    }));
  };

  const handleFriend = () => {
    webSocket.current.send(JSON.stringify({
      action: 'friendUserByUsername',
      username: username,
    }));
  };

  const handleSendMessage = () => {
    webSocket.current.send(JSON.stringify({
      action: 'messageUserByUsername',
      username: username,
    }));
  };

  const toggleExpansion = () => {
    setExpanded(!expanded);
  };

  return (
    <div className={`User ${expanded ? 'expanded' : ''}`}>
      {expanded ? (
        <>
            <Add onClick={toggleExpansion} className="expandUserIcon closeUserIcon" />
          <div className="profile-pic">
            <img src={`https://www.gravatar.com/avatar/${username}?d=identicon`} alt="Profile" />
          </div>
          <div className="user-details">
            <h2>{username}</h2>
          </div>
        </>
      ) : (
        <div className='userUnexpandedView'>
          <div className="profile-pic">
            <img src={`https://www.gravatar.com/avatar/${username}?d=identicon`} alt="Profile" />
          </div>
          <div className='usernameDiv'>
            <h2>{username}</h2>
          </div>
          <div className='iconDiv'>
            <Add onClick={toggleExpansion} className="expandUserIcon" />
          </div>
        </div>
      )}
      {expanded && (
        <div className="button-container">
          <button className="userButton report" onClick={handleReport}>Report</button>
          <button className="userButton friend" onClick={handleFriend}>Add Friend</button>
          <button className="userButton message" onClick={handleSendMessage}>Send Message</button>
        </div>
      )}
    </div>
  );
};

export default User;
