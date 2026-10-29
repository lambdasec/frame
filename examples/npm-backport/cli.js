const parseArgs = require("minimist");

const args = parseArgs(process.argv.slice(2));
console.log(`hello ${args.name || "world"}`);
