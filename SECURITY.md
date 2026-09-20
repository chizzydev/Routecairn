# Security Policy

## Dependency security

RouteCairn commits `package-lock.json` and uses `npm ci` in automation. Pull requests receive GitHub dependency review, while pushes, pull requests, scheduled runs, and manual runs execute a complete npm advisory audit. CI rejects any moderate, high, or critical advisory in production, optional, peer, or development dependencies.

Run the same controls locally:

```powershell
npm ci
npm run security:dependencies
```

`security:audit` accepts `--level info|low|moderate|high|critical` and an optional `--output <file>`. `security:sbom` accepts `--output-dir <directory>` and creates validated full-development and runtime-only CycloneDX JSON documents, a manifest, and SHA-256 checksums. Generated local evidence is excluded from source control.

Dependabot proposes weekly npm updates and monthly pinned GitHub Actions updates. Dependency-review and audit failures are not bypassed by an allowlist in the repository. If an upstream fix is temporarily unavailable, the change must remain blocked until maintainers make and document an explicit risk decision outside the automated gate.

## Release provenance

Tags matching `v*` build and test a fresh `npm ci` graph, create an npm package, generate its runtime SBOM, and issue GitHub/Sigstore attestations for both SLSA build provenance and the SBOM. The package, SBOMs, checksums, and attestation bundles are retained as workflow artifacts.

After downloading a release package, verify its repository identity with GitHub CLI:

```powershell
gh attestation verify .\routecairn-*.tgz --repo <owner>/RouteCairn
```

## Reporting a vulnerability

Do not place credentials, target evidence, or exploit details in a public issue. Use the repository's private security-advisory reporting channel when available. Include the affected version, a minimal reproduction using synthetic data, impact, and any known mitigation.
