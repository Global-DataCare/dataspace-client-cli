import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';

const execFileAsync = promisify(execFile);

test('help documents the extensible shared membership-scope contract', async () => {
  const { stdout } = await execFileAsync(process.execPath, ['bin/client-cli.js', '--help']);
  assert.match(stdout, /<service-category>:<membership-profile>/);
  assert.doesNotMatch(stdout, /vet-insurance:reader/);
});
