import React, { useState } from 'react';

function AddPostWindow({ addPost }) {
  const [postTitle, setPostTitle] = useState('');
  const [postContent, setPostContent] = useState('');
  const [imageUrl, setImageUrl] = useState('https://upload.wikimedia.org/wikipedia/commons/thumb/b/b6/Image_created_with_a_mobile_phone.png/1280px-Image_created_with_a_mobile_phone.png'); // New state for imageUrl
  const [keyWords, setKeyWords] = useState('');

  const handleAddPost = () => {
    const postId = generatePostId();
    const newPost = {
      id: postId,
      postTitle: postTitle,
      content: postContent,
      imageUrl: imageUrl, // Include imageUrl in the newPost object
      keyWords: keyWords.split(',').map(keyword => keyword.trim()),
      timestamp: new Date(),
      likes: 0,
      comments: []
    };
    addPost(newPost);
    // Clear input fields after adding post
    setPostTitle('');
    setPostContent('');
    setImageUrl(''); // Clear imageUrl state
    setKeyWords('');
  };

  const generatePostId = () => {
    return Math.random().toString(36).substr(2, 9);
  };

  return (
    <div className='addPostWindowContainer'>
      <div className="addPostWindow">
        <h2>Add New Post</h2>
        <div>
          <label htmlFor="post-title">Title:</label>
          <input
            type="text"
            id="post-title"
            value={postTitle}
            onChange={(e) => setPostTitle(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="post-content">Content:</label>
          <textarea
            id="post-content"
            value={postContent}
            onChange={(e) => setPostContent(e.target.value)}
          ></textarea>
        </div>
        <div>
          <label htmlFor="post-image-url">Image URL:</label> {/* New input for image URL */}
          <input
            type="text"
            id="post-image-url"
            value={imageUrl}
            onChange={(e) => setImageUrl(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="post-keywords">Keywords:</label>
          <input
            type="text"
            id="post-keywords"
            value={keyWords}
            onChange={(e) => setKeyWords(e.target.value)}
          />
        </div>
        <button onClick={handleAddPost}>Add Post</button>
      </div>
    </div>
  );
}

export default AddPostWindow;