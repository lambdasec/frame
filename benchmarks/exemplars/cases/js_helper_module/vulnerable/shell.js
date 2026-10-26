const { exec } = require('child_process');

function listDir(dir, cb) {
  exec('ls ' + dir, cb);
}

module.exports = { listDir };
