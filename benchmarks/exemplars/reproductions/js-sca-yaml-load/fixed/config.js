const yaml = require('js-yaml');
function parseConfig(raw){ return yaml.safeLoad(raw); }   // fixed: safeLoad, not the vulnerable load
module.exports = { parseConfig };
