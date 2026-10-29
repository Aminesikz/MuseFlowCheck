import React from 'react';

export default function Excerpt({ text }) {
  return <p className="excerpt">{text.slice(0, 140)}</p>;
}
