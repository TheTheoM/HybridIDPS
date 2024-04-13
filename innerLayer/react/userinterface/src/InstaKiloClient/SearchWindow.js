import React, { useState, useEffect, useRef } from 'react';
import Post from './Post';
import User from './User';
const SearchWindow = ({webSocket, searchValue, searchedUserList, searchedPostList, likePost, addCommentToPost}) => {

    useEffect(() => {
        if (searchValue.length > 0 && searchValue.trim() !== "") {
            webSocket.current.send(JSON.stringify({
              action: 'searchUsers',
              search: searchValue,
            }));
            webSocket.current.send(JSON.stringify({
                action: 'searchPosts',
                search: searchValue,
              }));
          }
    }, [searchValue])

    function handleUserClick() {
    
    }
    
    return (
        <div className="searchWindowContainer">
            <div className="searchWindow">
                <div className='searchedUsers'>
                    <h3>Users:</h3>
                    <div className='searchedUsersContainer'>
                        {searchedUserList  && Object.keys(searchedUserList).length > 0 ? (
                            Object.entries(searchedUserList).map(([username, user]) => (
                                //   <p key={username} onClick={() => handleUserClick(username)}>{username}</p>
                                <User username={username} imageUrl={user.imageUrl} likes = {user.likes} comments = {user.comments} hideUser = {user.hideUser} webSocket = {webSocket}/>
                            ))
                            ) : (
                            <p>No users named '{searchValue}' found.</p>
                        )}
                    </div> 
                </div>
                <div className='searchedPosts'>
                    <h3>Posts:</h3>
                    {(searchedPostList).length > 0 ? (
                        (searchedPostList).map(post => (
                            <Post username = {post.username} imageUrl = {post.imageUrl} likes = {post.likes} comments = {post.comments}
                                  content = {post.content} likePost = {likePost} postID = {post.id} addCommentToPost = {addCommentToPost}/>
                            // <p key={post.postTitle}>{post.postTitle}</p>
                        ))
                    ) : (
                        <p>No posts with matching title '{searchValue}' found.</p>
                    )}
                </div>
            </div>
        </div>
    );
};

export default SearchWindow;
