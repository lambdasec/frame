const shellEscape = require('shell-escape');

function clean(s) {
  return shellEscape([s]);
}

module.exports = { clean };
