const cp = require('child_process');
function runHost(host){ return cp.exec('nslookup ' + host); }  // vulnerable
module.exports = { runHost };
