const { readDoc } = require('./store');
function download(req){ return readDoc(req.params.name); }   // entry point
module.exports = { download };
