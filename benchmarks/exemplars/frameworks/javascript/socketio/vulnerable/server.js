const { Server } = require('socket.io');
const { exec } = require('child_process');
const fs = require('fs');

const io = new Server(3005);

io.on('connection', (socket) => {
  socket.on('chat', (msg) => {
    io.emit('chat', '<b>' + socket.id + '</b>: ' + msg);
  });

  socket.on('ping-host', (host, ack) => {
    exec('ping -c 1 ' + host, (err, out) => ack(out));  // frame-expect: CWE-78
  });

  socket.on('load-log', (data) => {
    const text = fs.readFileSync('/var/log/chat/' + data.name, 'utf8');  // frame-expect: CWE-22
    socket.emit('log', text);
  });
});
