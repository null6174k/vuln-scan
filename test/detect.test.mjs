import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { detectEcosystems } from '../lib/detect.mjs';

function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'vuln-scan-test-'));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('detects npm project from package.json', () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, 'package.json'), '{}');
    const found = detectEcosystems(dir);
    assert.equal(found.length, 1);
    assert.equal(found[0].ecosystem, 'npm');
  });
});

test('detects pip project from requirements.txt', () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, 'requirements.txt'), 'requests==2.0.0');
    const found = detectEcosystems(dir);
    assert.equal(found[0].ecosystem, 'pip');
  });
});

test('detects multiple ecosystems in a monorepo-style dir', () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, 'package.json'), '{}');
    writeFileSync(join(dir, 'Cargo.toml'), '[package]\nname="x"');
    const found = detectEcosystems(dir).map((e) => e.ecosystem).sort();
    assert.deepEqual(found, ['cargo', 'npm']);
  });
});

test('returns empty array when nothing recognized', () => {
  withTempDir((dir) => {
    const found = detectEcosystems(dir);
    assert.deepEqual(found, []);
  });
});
