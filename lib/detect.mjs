import { existsSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Detects which package ecosystems are present in a directory (repo root
 * or any subfolder — monorepos may have more than one).
 */
export function detectEcosystems(dir) {
  const found = [];

  if (existsSync(join(dir, 'package.json'))) {
    found.push({
      ecosystem: 'npm',
      lockfile: ['package-lock.json', 'npm-shrinkwrap.json'].find((f) =>
        existsSync(join(dir, f))
      ),
      manifest: 'package.json',
    });
  }

  if (
    existsSync(join(dir, 'requirements.txt')) ||
    existsSync(join(dir, 'pyproject.toml')) ||
    existsSync(join(dir, 'Pipfile'))
  ) {
    found.push({
      ecosystem: 'pip',
      manifest: ['requirements.txt', 'pyproject.toml', 'Pipfile'].find((f) =>
        existsSync(join(dir, f))
      ),
    });
  }

  if (existsSync(join(dir, 'Cargo.toml'))) {
    found.push({ ecosystem: 'cargo', manifest: 'Cargo.toml' });
  }

  if (existsSync(join(dir, 'go.mod'))) {
    found.push({ ecosystem: 'go', manifest: 'go.mod' });
  }

  return found;
}
