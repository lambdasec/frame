const { parseConfig } = require('./config');
function uploadConfig(req){ return parseConfig(req.body); }   // entry point: body is client-controlled
module.exports = { uploadConfig };
