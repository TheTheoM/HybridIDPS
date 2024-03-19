import React, { useState, useEffect, useRef } from 'react';
import Add from './Add';

function TopBar({ webSocket, searchedUserList, goToHome, setSearchValue, searchValue, showSearchWindow, setShowSearchWindow, setShowAddPostWindow}) {
  const [displaySearchedUsers, setDisplaySearchedUsers] = useState(false);
  const searchContainerRef = useRef(null);

  function handleKeyPress(event) {
    console.log("Search query:", event.target.value);
    setSearchValue(event.target.value);


  }

  useEffect(() => {
    function handleClickOutside(event) {
      if (searchContainerRef.current && !searchContainerRef.current.contains(event.target)) {
        setDisplaySearchedUsers(false);
      }
    }
    document.addEventListener("click", handleClickOutside);
    return () => {
      document.removeEventListener("click", handleClickOutside);
    };
  }, []);

  function handleUserClick(username) {
    setSearchValue(username);
    setDisplaySearchedUsers(false);
    setShowSearchWindow(1)
    
  }

  return (
    <div className='TopBar'>
      <div className='titleBox'>
        <h1 onClick = {goToHome} className='title'>InstaKilo</h1> <Add className="addPostBtn" onClick={() => {setShowAddPostWindow(1)}}/>
      </div>
      <div className='searchContainer' ref={searchContainerRef}>
        <input
          type="text"
          placeholder="Search"
          value={searchValue}
          onChange={handleKeyPress}
          onFocus={() => setDisplaySearchedUsers(true)}
        />
        
      </div>
    </div>
  );
}

export default TopBar;
