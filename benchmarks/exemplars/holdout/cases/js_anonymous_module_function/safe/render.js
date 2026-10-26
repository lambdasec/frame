const { execSync } = require('child_process');

module.exports = function (file) {
  return execSync('convert ' + file + ' out.png');
};
