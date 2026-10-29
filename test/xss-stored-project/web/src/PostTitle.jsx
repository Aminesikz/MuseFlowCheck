import React from 'react';
import DOMPurify from 'dompurify';

export default function PostTitle({ title }) {
  return <h1 dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(title) }} />;
}
