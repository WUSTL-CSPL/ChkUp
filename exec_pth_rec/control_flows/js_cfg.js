const esgraph = require("esgraph");
const esprima = require("esprima");

source = process.argv[2];

// Parse the source code and create a control flow graph
const parsed = esprima.parse(source, { range: true }); 
const cfg = esgraph(parsed);
const options = { counter: 0, source };
const dot = esgraph.dot(cfg, options);
console.log(dot);
