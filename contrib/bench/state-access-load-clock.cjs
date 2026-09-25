'use strict';
const fs = require('node:fs');
const zlib = require('node:zlib');
const readline = require('node:readline');
const assert = require('node:assert/strict');

// Inclusion can lag submission by minutes. Never start the clock at first inclusion.
async function loadOrigin(file) {
  const input = fs.createReadStream(file), decoded = input.pipe(zlib.createGunzip());
  const lines = readline.createInterface({input: decoded});
  try {
    for await (const line of lines) {
      const sample = JSON.parse(line);
      assert.ok(Number.isFinite(sample.unix_ms) && Number.isFinite(sample.offset_ms));
      return sample.unix_ms - sample.offset_ms;
    }
    throw new Error('empty metric archive');
  } finally {
    lines.close(); decoded.destroy(); input.destroy();
  }
}
module.exports = {loadOrigin};
