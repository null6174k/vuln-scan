const ICONS = {
  'override-applied': '✅',
  'safe-fix-available': '🟡',
  'requires-major-bump': '🔴',
  'no-fix-available': '⚪',
  'resolved-as-side-effect': '✅',
  'see-govulncheck-output': '🔵',
};

export function printReport(results) {
  let worst = 0; // exit code driver: any requires-major-bump or no-fix-available with high/critical severity
  let printedAny = false;

  for (const result of results) {
    console.log(`\n=== ${result.ecosystem} (${result.dir ?? '.'}) ===`);
    if (result.error) {
      console.log(`  ⚠️  ${result.error}`);
      continue;
    }
    if (result.total === 0) {
      console.log('  ✅ no known vulnerabilities');
      continue;
    }
    printedAny = true;
    for (const f of result.findings) {
      const icon = ICONS[f.resolution] ?? '❓';
      const sev = f.severity ? ` [${f.severity}]` : '';
      console.log(`  ${icon} ${f.package}${sev} — ${f.resolution}`);
      if (f.detail) console.log(`      ${f.detail}`);
      if (f.id) console.log(`      ${f.id}`);
      if (
        (f.resolution === 'requires-major-bump' || f.resolution === 'no-fix-available') &&
        (f.severity === 'high' || f.severity === 'critical')
      ) {
        worst = Math.max(worst, 1);
      }
    }
  }

  if (printedAny) {
    console.log(
      '\nLegend: ✅ fixed via override (no breaking change)   🟡 safe fix available   🔴 needs a breaking change or manual review   ⚪ no fix published yet'
    );
  }

  return worst; // 0 = clean/ok, 1 = unresolved high/critical remains
}

export function toJson(results) {
  return JSON.stringify(results, null, 2);
}
