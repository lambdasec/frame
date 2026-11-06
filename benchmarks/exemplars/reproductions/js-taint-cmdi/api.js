const { runHost } = require('./exec');
function lookup(req){ return runHost(req.query.host); }        // entry point
module.exports = { lookup };
