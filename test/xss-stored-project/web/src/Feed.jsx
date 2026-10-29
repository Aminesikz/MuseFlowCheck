import React, { useEffect, useState } from 'react';
import { getPost } from './client.js';
import PostBody from './PostBody.jsx';
import PostTitle from './PostTitle.jsx';
import Excerpt from './Excerpt.jsx';

export default function Feed({ id }) {
  const [post, setPost] = useState(null);

  useEffect(() => {
    getPost(id).then((p) => setPost(p));
  }, [id]);

  if (!post) return <p>Loading…</p>;
  return (
    <main>
      <PostTitle title={post.title} />
      <PostBody html={post.body} />
      <Excerpt text={post.body} />
      <p>By {post.author}</p>
    </main>
  );
}
