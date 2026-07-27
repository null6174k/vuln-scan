import { execFileSync } from 'node:child_process';

function toolAvailable(cmd, versionFlag = '--version') {
  try {
    execFileSync(cmd, [versionFlag], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

export function auditCargo(dir) {
  if (!toolAvailable('cargo-audit')) {
    return {
      ecosystem: 'cargo',
      error: 'cargo-audit not installed — run: cargo install cargo-audit',
    };
  }
  let out;
  try {
    out = execFileSync('cargo', ['audit', '--json'], {
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
    return { ecosystem: 'cargo', error: 'cargo audit did not return parseable JSON' };
  }
  const findings = (parsed.vulnerabilities?.list ?? []).map((v) => ({
    package: v.package.name,
    installedVersion: v.package.version,
    id: v.advisory.id,
    severity: v.advisory.severity ?? 'unknown',
    patchedVersions: v.versions?.patched ?? [],
    resolution: v.versions?.patched?.length ? 'safe-fix-available' : 'no-fix-available',
  }));
  return { ecosystem: 'cargo', dir, total: findings.length, findings };
}

export function auditGo(dir) {
  if (!toolAvailable('govulncheck')) {
    return {
      ecosystem: 'go',
      error: 'govulncheck not installed — run: go install golang.org/x/vuln/cmd/govulncheck@latest',
    };
  }
  let out;
  try {
    out = execFileSync('govulncheck', ['-json', './...'], {
      cwd: dir,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 50,
    });
  } catch (err) {
    out = err.stdout?.toString() ?? '';
  }
  const findings = [];
  for (const line of out.split('\n').filter(Boolean)) {
    try {
      const obj = JSON.parse(line);
      if (obj.finding) {
        findings.push({
          package: obj.finding.osv,
          resolution: 'see-govulncheck-output',
        });
      }
    } catch {
      /* govulncheck streams multiple JSON objects; skip unparsable lines */
    }
  }
  return { ecosystem: 'go', dir, total: findings.length, findings };
}
