# Public v2 reference evidence

This reference contains three real executions of 576 public behavior fixtures on Windows, Node 24.13.0, Python 3.12.10 and Go 1.27.1. The scanner release is 0.1.0; the corpus version is 2.0.0. The working tree contained the implementation under review. The scanner reports were subsequently scored with the current evaluator to include explicit provenance and confidence interval rendering.

The corpus has 288 vulnerable and 288 negative cases per repetition, including 144 near-miss controls. Twelve categories are exercised through four server frameworks in three languages. Python's HTTP and WSGI transports share handler logic. Injection fixtures include simulated vulnerable behavior. These data establish regression performance on this corpus, not independent real-world accuracy.

The manifest explicitly declares `SELF_MAINTAINED`, `blinded: false`, fixture execution and no external target testing. No independent verification artifact is present. An independently administered publisher/operator workflow is documented in `docs/INDEPENDENT_BENCHMARK.md`.

## Retained files

- `benchmark-manifest.json`: exact executed corpus contract.
- `benchmark-result.json`, `benchmark-report.md`, `benchmark-junit.xml`: scorecard and gates.
- `reports/run-{1,2,3}.json.gz`: compressed raw merged scanner reports, including target case observations and request audits.
- `reports/run-{1,2,3}-telemetry.json`: measured scanner runtime, RSS, CPU and transmission counts.
- `evidence-checksums.json`: compressed/uncompressed report checksums, runtime versions and provenance limits.

## Reproduce scoring

From the repository root, build RouteCairn and decompress the reports. This command verifies both compressed and uncompressed byte commitments before writing temporary files:

```powershell
npm run build
@'
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { gunzipSync } from "node:zlib";
import { createHash } from "node:crypto";
const root = "benchmarks/scorecards/2.0.0/reference-windows-node24";
const output = ".routecairn-credibility-replay";
const checksums = JSON.parse(await readFile(`${root}/evidence-checksums.json`, "utf8"));
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
await mkdir(output, { recursive: true });
for (let i = 1; i <= 3; i++) {
  const name = `reports/run-${i}.json.gz`;
  const compressed = await readFile(`${root}/${name}`);
  const raw = gunzipSync(compressed);
  if (hash(compressed) !== checksums.reports[name].compressedSha256 || hash(raw) !== checksums.reports[name].uncompressedSha256) throw new Error("EVIDENCE_CHECKSUM_MISMATCH");
  await writeFile(`${output}/run-${i}.json`, raw);
}
'@ | node --input-type=module
node dist/cli/index.js benchmark evaluate `
  --manifest benchmarks/scorecards/2.0.0/reference-windows-node24/benchmark-manifest.json `
  --reports .routecairn-credibility-replay/run-1.json .routecairn-credibility-replay/run-2.json .routecairn-credibility-replay/run-3.json `
  --telemetry benchmarks/scorecards/2.0.0/reference-windows-node24/reports/run-1-telemetry.json benchmarks/scorecards/2.0.0/reference-windows-node24/reports/run-2-telemetry.json benchmarks/scorecards/2.0.0/reference-windows-node24/reports/run-3-telemetry.json `
  --baseline benchmarks/scorecards/2.0.0/reference-windows-node24/benchmark-result.json `
  --output .routecairn-credibility-replay/evaluated
```

For a new live fixture execution, use `benchmark credibility --repetitions 3 --python <python-command> --go <go-command> --output <parent-directory>`. Resource envelopes are scanner-process measurements. Retain new reports and telemetry before accepting a new baseline.
