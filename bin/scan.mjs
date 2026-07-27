#!/usr/bin/env node
import { resolve } from 'node:path';
import { writeFileSync } from 'node:fs';
import { detectEcosystems } from '../lib/detect.mjs';
import { auditNpm } from '../lib/npm.mjs';
import { auditPip } from '../lib/pip.mjs';
import { auditCargo, auditGo } from '../lib/other.mjs';
import { printReport, toJson } from '../lib/report.mjs';

function parseArgs(argv) {
  const args = { dir: '.', apply: false, json: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--apply') args.apply = true;
    else if (a === '--json') args.json = argv[++i] ?? 'vuln-report.json';
    else if (a === '--help' || a === '-h') args.help = true;
    else args.dir = a;
  }
  return args;
}

function usage() {
  console.log(`vuln-scan — auto-detects the ecosystem(s) in a repo and audits for known vulnerabilities.

Usage:
  vuln-scan [dir] [options]

Options:
  --apply         Actually apply fixes: safe (non-breaking) fixes via the
                   package manager, and for npm, try pinning transitive
                   deps via "overrides" before ever suggesting a breaking
                   bump. Without this flag, scan is report-only.
  --json <file>   Also write the full structured report to a JSON file.
  --help          Show this help.

Exit code is 1 if any high/critical vulnerability remains unresolved
after the scan (useful for CI).`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    usage();
    return;
  }

  const dir = resolve(args.dir);
  const ecosystems = detectEcosystems(dir);

  if (ecosystems.length === 0) {
    console.log(`No recognized package manifests found in ${dir}`);
    process.exit(0);
  }

  console.log(
    `Detected: ${ecosystems.map((e) => e.ecosystem).join(', ')} — scanning${args.apply ? ' (apply mode)' : ' (report-only, use --apply to fix)'}...`
  );

  const results = [];
  for (const eco of ecosystems) {
    if (eco.ecosystem === 'npm') results.push(auditNpm(dir, { apply: args.apply }));
    else if (eco.ecosystem === 'pip') results.push(auditPip(dir));
    else if (eco.ecosystem === 'cargo') results.push(auditCargo(dir));
    else if (eco.ecosystem === 'go') results.push(auditGo(dir));
  }

  const exitCode = printReport(results);

  if (args.json) {
    writeFileSync(args.json, toJson(results));
    console.log(`\nFull report written to ${args.json}`);
  }

  process.exit(exitCode);
}

main();
