import { execFileSync } from 'node:child_process';

function toolAvailable(cmd) {
  try {
    execFileSync(cmd, ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

export function auditPip(dir) {
  if (!toolAvailable('pip-audit')) {
    return {
      ecosystem: 'pip',
      error: 'pip-audit not installed — run: pip install pip-audit --break-system-packages',
    };
  }

  let out;
  try {
    out = execFileSync('pip-audit', ['-f', 'json'], {
      cwd: dir,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 50,
    });
  } catch (err) {
    out = err.stdout?.toString() ?? '';
  }

  let parsed;
  try {
    parsed = JSON.parse(out);
  } catch {
    return { ecosystem: 'pip', error: 'pip-audit did not return parseable JSON' };
  }

  const deps = parsed.dependencies ?? parsed; // pip-audit JSON shape varies by version
  const findings = [];
  for (const dep of deps) {
    for (const vuln of dep.vulns ?? []) {
      findings.push({
        package: dep.name,
        installedVersion: dep.version,
        id: vuln.id,
        fixVersions: vuln.fix_versions ?? [],
        resolution: vuln.fix_versions?.length ? 'safe-fix-available' : 'no-fix-available',
      });
    }
  }

  return { ecosystem: 'pip', dir, total: findings.length, findings };
}
