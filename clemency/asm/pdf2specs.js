const fs = require('fs');
const lines = ('' + fs.readFileSync('../third_party/clemency.txt')).split(/\n/g);
const firstOp = 'AD';
let start = false;

const ops = {};
let currentOp = '';
let parsingOffsets = false;
let opRange = [];

function asPairs (arr) {
  const res = [];
  let pair = [];
  for (let a of arr) {
    pair.push(a);
    if (pair.length === 2) {
      res.push(pair);
      pair = [];
    }
  }
  return res;
}

for (let line of lines) {
  const word = line.split(':');
  if (word.length === 2 && word[0].length < 6) {
    if (line.indexOf('. . .') !== -1) {
      continue;
    }
    if (!start) {
      if (firstOp !== word[0]) {
        continue;
      }
      start = true;
    }
    if (word[0].toUpperCase() !== word[0] || +word[0]) {
      continue;
    }
    currentOp = word[0];
    ops[word[0]] = {
      title: ('' + word[1]).trim()
    };
    // console.log(line);
  } else {
    if (start && word.length >= 2) {
      switch (word[0]) {
        case 'Format':
          ops[currentOp].format = word[1].trim();
          break;
        case 'Purpose':
          ops[currentOp].purpose = word[1].trim();
          break;
        case 'Operation':
          ops[currentOp].operation = word[1].trim();
          break;
        case 'Description':
          ops[currentOp].description = word[1].trim();
          break;
        case 'Flags affected':
          ops[currentOp].flags = word[1].trim().split();
          break;
        default:
    //      console.log(currentOp, line);
      }
    } else {
      if (currentOp) {
        if (parsingOffsets) {
          if (line.indexOf('rA') !== -1 || line.indexOf('.') !== -1) {
            if (line.indexOf('rA') !== -1 && (line[0] === '0' || line[0] === '1')) {
              ops[currentOp].bytes = line.split(' ')[0];
              parsingOffsets = false;
            }
          } else {
            const offs = line.trim().split(' ').map(_ => +_);
            opRange.push(...offs);
            ops[currentOp].bits = asPairs(opRange);
            opRange = [];
          }
        } else if (line.trim() === '0') {
          parsingOffsets = true;
          opRange.push(0);
//          console.log(currentOp, line);
        }
      }
    }
  }
}

console.log(JSON.stringify(ops, null, 2));
