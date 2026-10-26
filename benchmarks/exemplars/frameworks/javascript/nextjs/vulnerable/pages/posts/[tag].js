import { findPosts } from '../../lib/db';

export async function getServerSideProps(context) {
  const posts = await findPosts(context.params.tag);
  return { props: { posts } };
}

export default function Posts({ posts }) {
  return <ul>{posts.map((p) => <li key={p.id}>{p.title}</li>)}</ul>;
}
