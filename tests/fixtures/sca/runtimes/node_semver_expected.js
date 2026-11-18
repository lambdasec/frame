const semver = require('semver'); const fs = require('fs');
const [vulnsF, relsF] = process.argv.slice(2);
const vulns = JSON.parse(fs.readFileSync(vulnsF)); const rels = JSON.parse(fs.readFileSync(relsF));
const versions = rels.map(r => r.version.replace(/^v/, '')).filter(v => /^\d+\.\d+\.\d+$/.test(v));
const out = {};
for (const [k, v] of Object.entries(vulns)) {
  out[k] = versions.filter(r => semver.satisfies(r, v.vulnerable) && !(v.patched && semver.satisfies(r, v.patched)));
}
console.log(JSON.stringify(out));
