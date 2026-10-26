import { findPosts } from '../../lib/db';

export default async function handler(req, res) {
  const posts = await findPosts(req.query.tag);
  res.status(200).json(posts);
}
