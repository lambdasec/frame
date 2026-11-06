const yaml = require('js-yaml');
function parseConfig(raw){ return yaml.load(raw); }   // CWE-502: js-yaml.load on attacker data
module.exports = { parseConfig };
