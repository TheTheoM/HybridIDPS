import React, { useState, useEffect, useRef } from 'react';

import Post from "./Post"
import User from "./User"

function Content({ webSocket, searchedUserList, goToHome, setSearchValue, searchValue, showSearchWindow, setShowSearchWindow, postList, likePost, addCommentToPost }) {
  const [selectedUserName, setSelectedUserName] = useState("")

  useEffect(() => {
    const loginData = {
      action: 'getPostList',
    };
    webSocket.current.send(JSON.stringify(loginData));
  }, [])
  
  function showUserByName(username) {
    setSelectedUserName(username)
    setShowSearchWindow(1)
  }
  
  function hideUser () {
    setSelectedUserName("")
    setSearchValue("")
    setShowSearchWindow(0)
  }

  useEffect(() => {
    console.log(postList)
  }, [postList])
  
  const post = {
    username: 'hiCunt',
    imageUrl: 'https://upload.wikimedia.org/wikipedia/commons/thumb/b/b6/Image_created_with_a_mobile_phone.png/1280px-Image_created_with_a_mobile_phone.png',
    likes: 42,
    content: "The ethereal glow of dawn cascaded through the forest, painting the leaves in hues of gold and amber.",
    comments: [
      { username: 'user1', text: 'Nice rack!' },
      { username: 'user2', text: 'Awesome!' },
      { username: 'user3', text: 'Great photo!' }
    ]
  };
  
//   <div className='UserContainer'>
//   <User hideUser = {hideUser} username={selectedUserName} webSocket = {webSocket}/>
// </div>
  
  return (
   <div className='contentContainer'>
    <div className='Content'>
      {postList  && Object.keys(postList).length > 0 ? (
          Object.entries(postList).map(([username, user]) => (
              <Post username={user.username} imageUrl={user.imageUrl} content = {user.content} likes = {user.likes} comments = {user.comments} 
                    hideUser = {user.hideUser} webSocket = {webSocket} likePost = {likePost} postID = {user.id} addCommentToPost = {addCommentToPost}/>
            ))
          ) : (
          <p>No posts found.</p>
      )}
      {/* <Post
        username = {post.username}
        imageUrl = {post.imageUrl}
        likes    = {post.likes}
        comments = {post.comments}
        content  = {post.content}
        showUserByName = {showUserByName}
      />
      <Post
        username = {post.username}
        imageUrl = {post.imageUrl}
        likes    = {post.likes}
        comments = {post.comments}
        content  = {post.content}
        showUserByName = {showUserByName}
      /> */}
    </div>
   </div>
  );
}


export default Content;
