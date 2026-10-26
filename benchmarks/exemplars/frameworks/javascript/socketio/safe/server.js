const { Server } = require('socket.io');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const io = new Server(3005);

io.on('connection', (socket) => {
  socket.on('chat', (msg) => {
    io.emit('chat', socket.id, msg);
  });

  socket.on('ping-host', (host, ack) => {
    execFile('ping', ['-c', '1', host], (err, out) => ack(out));
  });

  socket.on('load-log', (data) => {
    const text = fs.readFileSync(path.join('/var/log/chat', path.basename(data.name)), 'utf8');
    socket.emit('log', text);
  });
});
