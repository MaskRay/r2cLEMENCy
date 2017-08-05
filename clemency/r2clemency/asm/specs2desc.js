const fs = require('fs');
const ops = JSON.parse(''+ fs.readFileSync('asm/specs.json'));
for (let op in ops) {
  console.log(op.toLowerCase() + '=' + ops[op].title.toLowerCase());
}
