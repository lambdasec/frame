const fs = require('fs');
function readDoc(name){ return fs.readFileSync('/srv/docs/' + name); }  // CWE-22
module.exports = { readDoc };
