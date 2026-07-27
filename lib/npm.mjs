import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

function run(cmd, args, cwd) {
  try {
    const out = execFileSync(cmd, args, {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 1024 * 1024 * 50,
    });
    return { ok: true, out };
  } catch (err) {
    // npm audit exits non-zero when vulnerabilities exist — stdout still has the JSON.
    return { ok: false, out: err.stdout?.toString() ?? '', err: err.stderr?.toString() ?? '' };
  }
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/**
 * Runs `npm audit --json`, returns the parsed vulnerability list.
 */
function auditJson(dir) {
  const res = run('npm', ['audit', '--json'], dir);
  if (!res.out) return null;
  try {
    return JSON.parse(res.out);
  } catch {
    return null;
  }
}

/**
 * For a package that's only reachable as a transitive dependency, checks
 * whether pinning it to its patched version via `overrides` is compatible
 * with what its parent(s) already declare — i.e. whether we can fix the
 * CVE without forcing a major-version bump of a direct dependency (the
 * "sharp trick": Next.js accepted sharp ^0.34.3, the patched 0.35.3 still
 * satisfies that range, so an override closes the CVE with zero blast
 * radius instead of downgrading Next itself).
 */
function latestVersion(pkgName, dir) {
  const res = run('npm', ['view', pkgName, 'version'], dir);
  return res.ok ? res.out.trim() : null;
}

function installedVersion(pkgName, dir) {
  const res = run('npm', ['ls', pkgName, '--json', '--all'], dir);
  try {
    const tree = JSON.parse(res.out || '{}');
    const found = (function search(node) {
      if (!node?.dependencies) return null;
      for (const [name, info] of Object.entries(node.dependencies)) {
        if (name === pkgName && info.version) return info.version;
        const nested = search(info);
        if (nested) return nested;
      }
      return null;
    })(tree);
    return found;
  } catch {
    return null;
  }
}

/**
 * NOTE: the `fixAvailable.version` field from `npm audit` for a transitive
 * vulnerability names the *parent* package npm suggests bumping (e.g.
 * "next"), not a patched version of pkgName itself — using it as pkgName's
 * override target silently produces an invalid version range, which npm
 * then drops instead of installing (looks "fixed" in a re-audit only
 * because the package vanished, not because it's patched). So we ignore
 * fixAvailable.version here and resolve pkgName's own latest version
 * from the registry instead, then verify it's genuinely present in the
 * tree afterward — not just absent.
 */
function tryOverrideFix(dir, pkgName) {
  const manifestPath = join(dir, 'package.json');
  const original = readFileSync(manifestPath, 'utf8');
  const manifest = JSON.parse(original);

  const isDirect =
    manifest.dependencies?.[pkgName] || manifest.devDependencies?.[pkgName];
  if (isDirect) {
    return { applied: false, reason: 'direct-dependency' };
  }

  const latest = latestVersion(pkgName, dir);
  if (!latest) {
    return { applied: false, reason: 'could-not-resolve-latest-version' };
  }

  manifest.overrides = { ...(manifest.overrides ?? {}), [pkgName]: `^${latest}` };
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');

  const install = run('npm', ['install', '--no-audit', '--no-fund'], dir);
  const gotVersion = installedVersion(pkgName, dir);

  if (!install.ok || !gotVersion) {
    writeFileSync(manifestPath, original);
    run('npm', ['install', '--no-audit', '--no-fund'], dir);
    return {
      applied: false,
      reason: !install.ok ? 'install-conflict' : 'package-silently-dropped',
      detail: !install.ok
        ? install.err.slice(0, 400)
        : `override ^${latest} resolved to nothing installed`,
    };
  }

  const reaudit = auditJson(dir);
  const stillVulnerable = reaudit?.vulnerabilities?.[pkgName];
  if (stillVulnerable) {
    writeFileSync(manifestPath, original);
    run('npm', ['install', '--no-audit', '--no-fund'], dir);
    return { applied: false, reason: 'still-vulnerable-after-override' };
  }

  return { applied: true, reason: 'override-applied', version: gotVersion };
}

/**
 * Audits an npm project. By default (apply=false) this only reports —
 * it never edits package.json unless apply is true.
 */
export function auditNpm(dir, { apply = false } = {}) {
  if (!existsSync(join(dir, 'package.json'))) {
    return { ecosystem: 'npm', error: 'no package.json found' };
  }
  if (!existsSync(join(dir, 'node_modules'))) {
    run('npm', ['install', '--no-audit', '--no-fund'], dir);
  }

  const before = auditJson(dir);
  if (!before) {
    return { ecosystem: 'npm', error: 'npm audit did not return JSON (offline or npm error?)' };
  }

  const resolutionNotes = {}; // package -> { resolution, detail } for entries we actively fixed

  if (apply) {
    // Handle the plain safe-fix cases first with the real `npm audit fix` (no --force).
    const hasSafeFixes = Object.values(before.vulnerabilities ?? {}).some(
      (v) => v.fixAvailable === true
    );
    if (hasSafeFixes) run('npm', ['audit', 'fix'], dir);

    // Then attempt the override trick for anything npm would otherwise want
    // a breaking bump for.
    for (const [name, vuln] of Object.entries(before.vulnerabilities ?? {})) {
      const fix = vuln.fixAvailable;
      if (fix && typeof fix === 'object' && fix.isSemVerMajor) {
        const attempt = tryOverrideFix(dir, name);
        resolutionNotes[name] = attempt.applied
          ? {
              resolution: 'override-applied',
              detail: `pinned via overrides to ^${attempt.version}, no top-level version changed`,
            }
          : {
              resolution: 'requires-major-bump',
              detail: `${attempt.reason}${attempt.detail ? ': ' + attempt.detail : ''} — npm's own suggestion would need ${fix.name}@${fix.version} directly (breaking)`,
            };
      }
    }
  }

  // Always finish with a fresh audit so the report reflects reality —
  // fixing one package can resolve others reported against it (e.g. a
  // transitive vuln and the direct dependency that pulled it in both
  // disappear once the transitive package itself is patched).
  const after = apply ? auditJson(dir) ?? before : before;

  const findings = [];
  for (const [name, vuln] of Object.entries(after.vulnerabilities ?? {})) {
    const entry = {
      package: name,
      severity: vuln.severity,
      via: (vuln.via ?? [])
        .map((v) => (typeof v === 'string' ? v : v.title))
        .filter(Boolean),
      range: vuln.range,
      directDependency: vuln.isDirect === true,
      resolution: 'no-fix-available',
      detail: null,
    };

    if (resolutionNotes[name]) {
      Object.assign(entry, resolutionNotes[name]);
    } else {
      const fix = vuln.fixAvailable;
      if (fix === true) {
        entry.resolution = 'safe-fix-available';
      } else if (fix && typeof fix === 'object') {
        if (fix.isSemVerMajor) {
          entry.resolution = 'requires-major-bump';
          entry.detail = `default fix bumps ${fix.name} to ${fix.version} (breaking) — worth checking if an override avoids this`;
        } else {
          entry.resolution = 'safe-fix-available';
          entry.detail = `${fix.name}@${fix.version}`;
        }
      }
    }

    findings.push(entry);
  }

  // Packages that were vulnerable before but no longer appear at all in
  // `after` (not just "resolution changed") were fixed as a side effect —
  // e.g. a direct dependency's only listed vuln was caused by the
  // transitive package we just patched.
  if (apply) {
    for (const name of Object.keys(before.vulnerabilities ?? {})) {
      if (!after.vulnerabilities?.[name] && !findings.some((f) => f.package === name)) {
        findings.push({
          package: name,
          severity: before.vulnerabilities[name].severity,
          resolution: 'resolved-as-side-effect',
          detail: 'no longer flagged after fixing a related package',
        });
      }
    }
  }

  return {
    ecosystem: 'npm',
    dir,
    total: findings.length,
    findings: findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
  };
}

function severityRank(sev) {
  return { critical: 4, high: 3, moderate: 2, low: 1 }[sev] ?? 0;
}
