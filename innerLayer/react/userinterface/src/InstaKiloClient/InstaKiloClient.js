import React, { useState, useEffect, useRef } from 'react';
import TopBar from "./TopBar"
import Footer from "./Footer"
import Content from "./Content"
import SearchWindow from "./SearchWindow"
import AddPostWindow from './AddPostWindow';

function InstaKiloClient({username, password, webSocket, requestedUserData, searchedUserList, searchedPostList, postList}) {
  const [globalShowUser, setGlobalShowUser] = useState("")
  const [searchValue, setSearchValue] = useState("")
  const [showSearchWindow, setShowSearchWindow] = useState(0)
  const [showAddPostWindow, setShowAddPostWindow] = useState(0)
  
  useEffect(() => {
    if (typeof searchValue !== "undefined" && searchValue.trim() !== '' && searchValue.length > 0) {
      setShowSearchWindow(1)
    } else {
      setShowSearchWindow(0)
      
    }
    }, [searchValue])
  
  function showUserFunc(username) {
    setGlobalShowUser(username)
  }

  function goToHome() {
    setShowSearchWindow(0)
    setSearchValue('')
    setShowAddPostWindow(0)
  }

  function addPost(newPost) {
    goToHome()
    webSocket.current.send(JSON.stringify({
      'action': 'addPost',
      'username': username,
      'id': newPost.postId,
      'postTitle': newPost.postTitle,
      'imageUrl':  newPost.imageUrl,
      'content': newPost.content,
      'keyWords': newPost.keyWords,
      'timestamp': new Date(),
      'likes': newPost.likes,
      'comments': newPost.comments,
    }))
  }

  function likePost(postID, increment) {
    webSocket.current.send(JSON.stringify({
      'action': 'likePost',
      'postID': postID,
      'increment': increment,
    }))
  }

  function addCommentToPost(postID, comment) {
    var username =  JSON.parse(localStorage.getItem("credentials")).username;
    console.log(username)
    webSocket.current.send(JSON.stringify({
      'action': 'addComment',
      'postID': postID,
      'comment': comment,
      'username': username,
    }))
  }

  useEffect(() => {
    console.log(postList)
  }, [postList])
  
  let contentToRender;

  if (showAddPostWindow && !showSearchWindow) {
    contentToRender = <AddPostWindow addPost={addPost}/>;
  } else if (showSearchWindow) {
    contentToRender = <SearchWindow webSocket={webSocket} searchValue={searchValue} searchedUserList={searchedUserList} searchedPostList={searchedPostList} likePost = {likePost} addCommentToPost = {addCommentToPost}/>;
  } else {
    contentToRender = <Content webSocket={webSocket} requestedUserData={requestedUserData} searchedPostList={searchedPostList} globalShowUser={globalShowUser} setGlobalShowUser={setGlobalShowUser}
                      setShowSearchWindow={setShowSearchWindow} postList = {postList} likePost = {likePost} addCommentToPost = {addCommentToPost}/>;
  }
  
  return (
    <>
      <TopBar  webSocket = {webSocket}  searchedUserList = {searchedUserList} goToHome = {goToHome} setSearchValue = {setSearchValue}
               searchValue = {searchValue} showSearchWindow = {showSearchWindow} setShowSearchWindow = {setShowSearchWindow}
               setShowAddPostWindow = {setShowAddPostWindow}/>

      {contentToRender}
      
      <Footer/>
    </>

  );
}

export default InstaKiloClient;
