export default function handler(req, res) {
  const { name } = req.query;
  res.setHeader('Content-Type', 'text/html');
  res.send('<h1>Hello ' + name + '</h1>');  // frame-expect: CWE-79
}
