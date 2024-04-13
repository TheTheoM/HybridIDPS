import React, { useState, useEffect, useRef } from 'react';
import Down from "./Down"
import Up from "./Up"
const Post = ({ username, imageUrl, likes, comments, content, likePost, postID, addCommentToPost}) => {
    const [isUpVoted, setIsUpVoted] = useState(0);
    const [isDownVoted, setIsDownVoted] = useState(0);
    const [newComment, setNewComment] = useState('');

    function handleUpvote() {
        setIsUpVoted(!isUpVoted);
        setIsDownVoted(0)
        let increment;
        if (!isUpVoted) {
            increment = 1;
        } else { 
            increment = -1;
        }
        likePost(postID, increment);
    }

    function handleDownvote() {
        setIsDownVoted(!isDownVoted);
        setIsUpVoted(0)
        let increment;
        if (!isDownVoted) {
            increment = -1;
        } else { 
            increment = +1;
        }
        likePost(postID, increment);
    }



    function handleCommentChange(event) {
        setNewComment(event.target.value);
    }

    function addComment() {
        if (newComment.trim() !== '') {
            addCommentToPost(postID, newComment)
            setNewComment('');
        }
    }

    return (
    <div className="post">
        <div className="post-header">
        <img
            className="post-avatar"
            src={`https://www.gravatar.com/avatar/${username}?d=identicon`}
            alt={`${username}'s avatar`}
        />
        <h3 className="post-username">{username}</h3>
        </div>
        <div className="post-image">
        <img src={imageUrl} alt="Post" />
        </div>
        <div className="post-footer">
        <p style={{'textAlign': 'left'}}> <strong>{username}:</strong> {content}</p>
        <div className="post-actions">
            <div className='votingContainer'>
                <Up style={isUpVoted ? { backgroundColor: '#00800044', color: 'green' } : { color: 'white' }} onClick={handleUpvote} />
                <Down style={isDownVoted ? {backgroundColor: '#80000044' , color: 'red' } : { color: 'white' }} onClick={handleDownvote} />
            </div>
            <div className="post-likes"><p>{likes} likes</p></div>
        </div>
        <div className="post-comments">
            {comments.map((comment, index) => (
            <div key={index} className="post-comment">
                <strong>{comment.username}:</strong> {comment.comment}
            </div>
            ))}
        </div>
        <div className='add-comments'>
            <input
                type="text"
                value={newComment}
                onChange={handleCommentChange}
                onKeyDown={(event) => {if (event.key === 'Enter') {addComment();}}}
                placeholder=" Add a comment..."
            />
            <button onClick={addComment}> Add </button>
        </div>
        </div>
    </div>
    );
};

export default Post;
