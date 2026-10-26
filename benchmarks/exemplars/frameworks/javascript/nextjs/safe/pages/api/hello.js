import escapeHtml from 'escape-html';

export default function handler(req, res) {
  const { name } = req.query;
  res.setHeader('Content-Type', 'text/html');
  res.send('<h1>Hello ' + escapeHtml(name) + '</h1>');
}
