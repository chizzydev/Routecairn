import { readFileSync, writeFileSync, lstatSync } from "node:fs";
import { resolve, join } from "node:path";
import { createHash } from "node:crypto";
import {
  prospectiveSourceExpectations,
  sealProspectivePredictions,
  verifyProspectiveRelease,
  revealProspectiveStudy,
  prospectiveStudySchema,
  type PracticalRun,
  type ProspectiveSeal,
  type OracleRelease
} from "../src/benchmark/ProspectiveAssessmentIntake.js";
const read = (p: string) => {
  const s = lstatSync(p);
  if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || s.size > 8388608)
    throw Error("PROSPECTIVE_BOUNDED_ORDINARY_FILE");
  const b = readFileSync(p);
  if (b.length > 8388608) throw Error("PROSPECTIVE_INPUT_BOUND");
  return b;
};
const [mode, manifestPath, expectedHash, ...args] = process.argv.slice(2);
if (!manifestPath || !expectedHash) throw Error("USAGE_SEAL_OR_REVEAL_EXACT_ARGUMENTS");
const bytes = read(resolve(manifestPath));
if (createHash("sha256").update(bytes).digest("hex") !== expectedHash) throw Error("PROSPECTIVE_PUBLIC_MANIFEST_HASH");
const m = prospectiveStudySchema.parse(JSON.parse(bytes.toString()));
let result: unknown, out: string;
if (mode === "seal" && args.length === 3) {
  const [runs, sourceRoot, output] = args,
    base = resolve(sourceRoot!);
  if (!lstatSync(base).isDirectory() || lstatSync(base).isSymbolicLink())
    throw Error("PROSPECTIVE_ORDINARY_SOURCE_ROOT");
  const bindings = prospectiveSourceExpectations(m).map((row) => {
    const parts = row.path.split("/");
    for (let i = 1; i < parts.length; i++) {
      const p = lstatSync(join(base, ...parts.slice(0, i)));
      if (!p.isDirectory() || p.isSymbolicLink()) throw Error("PROSPECTIVE_SOURCE_ANCESTOR");
    }
    const sha256 = createHash("sha256")
      .update(read(join(base, ...parts)))
      .digest("hex");
    if (sha256 !== row.sha256) throw Error("PROSPECTIVE_SOURCE_CHANGED");
    return { path: row.path, sha256 };
  });
  result = sealProspectivePredictions(m, JSON.parse(read(resolve(runs!)).toString()) as PracticalRun[], bindings);
  out = output!;
} else if (mode === "reveal" && args.length === 5) {
  const [sealed, release, key, oracle, output] = args,
    s = JSON.parse(read(resolve(sealed!)).toString()) as ProspectiveSeal,
    r = JSON.parse(read(resolve(release!)).toString()) as OracleRelease,
    pem = read(resolve(key!)).toString();
  // Verify the complete global seal and separately pinned release BEFORE opening any oracle file.
  verifyProspectiveRelease(m, s, r, pem);
  result = revealProspectiveStudy(m, s, r, pem, read(resolve(oracle!)));
  out = output!;
} else throw Error("PROSPECTIVE_EXACT_ARGUMENTS");
const b = Buffer.from(JSON.stringify(result, null, 2) + "\n");
if (b.length > 8388608) throw Error("PROSPECTIVE_OUTPUT_BOUND");
writeFileSync(resolve(out), b, { flag: "wx" });
console.log(
  JSON.stringify({
    mode,
    outputSha256: createHash("sha256").update(b).digest("hex"),
    independentAcceptance: false,
    executionAuthority: "NONE"
  })
);
