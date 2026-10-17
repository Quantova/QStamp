// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const DIRS = ['lib', 'bin', 'test', 'scripts'];
const HEADER = ['// Copyright 2026 Quantova Inc', '// SPDX-License-Identifier: Apache-2.0 OR MIT'];

function files() {
  const out = [path.join(ROOT, 'index.js')];
  for (const d of DIRS) {
    const dir = path.join(ROOT, d);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) if (f.endsWith('.js')) out.push(path.join(dir, f));
  }
  return out;
}

const problems = [];
for (const file of files()) {
  const rel = path.relative(ROOT, file);
  try {
    execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
  } catch (e) {
    problems.push(rel + ' does not parse');
    continue;
  }
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const start = lines[0].startsWith('#!') ? 1 : 0;
  if (lines[start] !== HEADER[0] || lines[start + 1] !== HEADER[1]) problems.push(rel + ' lacks the copyright and licence header');
  lines.forEach((line, i) => {
    if (i > start + 1 && /^\s*(\/\/|\/\*)/.test(line)) problems.push(rel + ':' + (i + 1) + ' holds a comment');
    if (/\s+$/.test(line)) problems.push(rel + ':' + (i + 1) + ' has trailing white space');
    if (/\t/.test(line)) problems.push(rel + ':' + (i + 1) + ' holds a tab');
    if (/[\u2028\u2029]/.test(line)) problems.push(rel + ':' + (i + 1) + ' holds a raw line separator');
  });
  if (!/^'use strict';$/m.test(lines.join('\n'))) problems.push(rel + ' is not in strict mode');
}
if (problems.length) {
  process.stderr.write(problems.join('\n') + '\n');
  process.exit(1);
}
process.stdout.write('lint passed for ' + files().length + ' files\n');
