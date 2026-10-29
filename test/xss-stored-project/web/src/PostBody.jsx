import React from 'react';

export default function PostBody({ html }) {
  return <div className="post-body" dangerouslySetInnerHTML={{ __html: html }} />;
}
