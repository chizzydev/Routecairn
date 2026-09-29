# Compatibility policy

RouteCairn uses Semantic Versioning for its public command line interface, configuration files, report schemas, worker protocol, database migrations, and documented extension API.

## Supported runtimes

| Surface | Supported versions | Policy |
| --- | --- | --- |
| Node.js | `^20.19`, `^22.19`, and `>=24` | Tested on active and maintenance LTS lines in CI. |
| SQLite | Bundled through `better-sqlite3` | The database is migrated forward on startup after a backup. |
| PostgreSQL | 16 and 17 | Schema migrations are forward compatible within a major RouteCairn release. |
| Chromium | Version installed by the pinned Playwright release | Other browser builds are outside the tested contract. |
| Linux, macOS, Windows | Current GitHub hosted images | Core build and platform boundary tests run on each release. |

## Versioned contracts

- JSON inputs with `schemaVersion` reject unknown major versions. Additive optional fields may appear in a minor release.
- Reports retain readers for the current major version and the previous major version. Producers always emit the current schema.
- Control plane and worker versions may differ by one minor version within the same major version. Capability negotiation must succeed before a job is leased.
- Plugins declare the host API range they support. RouteCairn rejects an incompatible range before module code is evaluated.
- Database migrations are one way. Operators must back up the database and object store before upgrading. Downgrade requires restoring that backup.

## Release and support window

Patch releases contain compatible fixes. Minor releases may add optional fields, capabilities, and migrations. Major releases may remove deprecated contracts. A deprecation remains documented for at least one minor release before removal. Security fixes are applied to the current minor release; critical fixes may also be backported to the previous minor release.

Every tagged release must pass the release policy gate, include a changelog entry, publish an SBOM and provenance attestation, and carry an accepted independent security review attestation for the release line.
