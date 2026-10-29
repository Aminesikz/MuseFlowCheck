export async function getPost(id) {
  const res = await fetch(`/forum/posts/${id}`);
  const data = await res.json();
  return data.post;
}
