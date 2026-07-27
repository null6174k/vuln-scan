# vuln-scan

Auto-detects the package ecosystem(s) in a repo (npm, pip, cargo, go) and
audits for known vulnerabilities. Its one opinion: **`--force`-style
breaking bumps are a last resort, not the default fix.**

For npm specifically, it tries the same move you'd do by hand — pin the
vulnerable *transitive* dependency to its own patched version via
`overrides`, verify it actually installs and the CVE clears, and only
fall back to reporting "needs a breaking change" if that genuinely
doesn't work. This is what turned "downgrade Next.js 15 → 14" into
"add one line to `overrides`" for ChainMind's `sharp` CVE.

## Install

```bash
cd vuln-scanner
npm install    # only needed if you add ecosystem-specific tools later
```

No dependencies beyond Node's built-ins — it shells out to whatever's
already on your machine (`npm`, `pip-audit`, `cargo-audit`,
`govulncheck`).

## Usage

```bash
# report-only, safe to run anywhere
node bin/scan.mjs /path/to/repo

# actually apply fixes (safe fixes via the package manager,
# override trick for transitive deps that would otherwise need
# a breaking bump)
node bin/scan.mjs /path/to/repo --apply

# also write the full structured report
node bin/scan.mjs /path/to/repo --apply --json report.json
```

Optionally link it globally:

```bash
npm link
vuln-scan .
```

Exit code is `1` if any high/critical vulnerability remains unresolved —
safe to use as a CI gate.

## What the icons mean

| Icon | Meaning |
| --- | --- |
| ✅ | Fixed — either a non-breaking override, or resolved as a side effect of fixing a related package |
| 🟡 | A safe (non-breaking) fix is available; run with `--apply` |
| 🔴 | No non-breaking path found — needs a manual look or an accepted breaking change |
| ⚪ | No fix published yet upstream |

## Ecosystem support

| Ecosystem | Requires | Apply mode |
| --- | --- | --- |
| npm | nothing extra | ✅ full (safe fixes + override trick) |
| pip | `pip install pip-audit` | report-only for now |
| cargo | `cargo install cargo-audit` | report-only for now |
| go | `go install golang.org/x/vuln/cmd/govulncheck@latest` | report-only for now |

## CI

`.github/workflows/vuln-scan.yml` runs the scan report-only on every
push/PR to `main` and weekly on a schedule (since new CVEs land against
unchanged code). It currently assumes the tool is published to npm as
`vuln-scan` — if you're not publishing it, swap that step for a
checkout + `npm link` of this repo (commented inline in the workflow).

## Tests

```bash
npm test
```
