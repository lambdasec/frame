const restify = require('restify');
const mysql = require('mysql');
const { exec } = require('child_process');

const db = mysql.createConnection({ host: 'localhost', user: 'api', database: 'inventory' });
const server = restify.createServer();

server.use(restify.plugins.queryParser());
server.use(restify.plugins.bodyParser());

server.get('/items/:sku', (req, res, next) => {
  db.query("SELECT * FROM items WHERE sku = '" + req.params.sku + "'", (err, rows) => {  // frame-expect: CWE-89
    res.send(rows);
    next();
  });
});

server.get('/hello', (req, res, next) => {
  res.setHeader('Content-Type', 'text/html');
  res.sendRaw('<p>Hello ' + req.query.name + '</p>');  // frame-expect: CWE-79
  next();
});

server.get('/go', (req, res, next) => {
  res.redirect(req.query.to, next);  // frame-expect: CWE-601
});

server.post('/label', (req, res, next) => {
  exec('print-label ' + req.body.sku);  // frame-expect: CWE-78
  res.send(202);
  next();
});

server.listen(8080);
