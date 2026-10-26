const restify = require('restify');
const mysql = require('mysql');
const { execFile } = require('child_process');
const escapeHtml = require('escape-html');

const db = mysql.createConnection({ host: 'localhost', user: 'api', database: 'inventory' });
const server = restify.createServer();

server.use(restify.plugins.queryParser());
server.use(restify.plugins.bodyParser());

server.get('/items/:sku', (req, res, next) => {
  db.query('SELECT * FROM items WHERE sku = ?', [req.params.sku], (err, rows) => {
    res.send(rows);
    next();
  });
});

server.get('/hello', (req, res, next) => {
  res.setHeader('Content-Type', 'text/html');
  res.sendRaw('<p>Hello ' + escapeHtml(req.query.name) + '</p>');
  next();
});

server.get('/go', (req, res, next) => {
  const to = req.query.to;
  if (to.startsWith('/') && !to.startsWith('//')) {
    res.redirect(to, next);
  } else {
    res.redirect('/', next);
  }
});

server.post('/label', (req, res, next) => {
  execFile('print-label', [req.body.sku]);
  res.send(202);
  next();
});

server.listen(8080);
