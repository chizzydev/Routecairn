import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { readEvaluationFile, evidenceRelativePath } from "../src/benchmark/BoundedEvaluationFiles.js";
import {
  sealEvaluationEvidence,
  verifyEvaluationWitness,
  scoreEvaluationEvidence,
  type EvaluationWitness
} from "../src/benchmark/IndependentEvaluationEvidence.js";
import {
  prospectiveStudySchema,
  type ProspectiveSeal,
  type OracleRelease
} from "../src/benchmark/ProspectiveAssessmentIntake.js";
const json = (p: string) => JSON.parse(readEvaluationFile(p).toString("utf8"));
const [mode, manifestPath, expectedHash, ...args] = process.argv.slice(2);
if (!manifestPath || !expectedHash) throw Error("EVALUATION_EXACT_ARGUMENTS");
const bytes = readEvaluationFile(manifestPath);
if (createHash("sha256").update(bytes).digest("hex") !== expectedHash) throw Error("EVALUATION_PUBLIC_MANIFEST_HASH");
const m = prospectiveStudySchema.parse(JSON.parse(bytes.toString("utf8")));
let output: string, result: unknown;
if (mode === "seal-evidence" && args.length === 5) {
  const [enrollment, sealed, catalog, evidenceRoot, out] = args;
  result = sealEvaluationEvidence(m, json(enrollment!), json(sealed!) as ProspectiveSeal, json(catalog!), (p) =>
    readEvaluationFile(evidenceRelativePath(evidenceRoot!, p))
  );
  output = out!;
} else if (mode === "score-evidence" && args.length === 7) {
  const [sealed, release, key, witness, signature, oracle, out] = args,
    s = json(sealed!) as ProspectiveSeal,
    r = json(release!) as OracleRelease,
    pem = readEvaluationFile(key!).toString("utf8"),
    w = json(witness!) as EvaluationWitness,
    sig = readEvaluationFile(signature!).toString("utf8").trim();
  // Both pinned signatures and complete prediction binding are checked BEFORE opening private labels.
  verifyEvaluationWitness(m, s, r, pem, w, sig);
  result = scoreEvaluationEvidence(m, s, r, pem, w, sig, readEvaluationFile(oracle!));
  output = out!;
} else throw Error("EVALUATION_EXACT_ARGUMENTS_NO_LABEL_ARGUMENT_ON_SEAL");
const out = Buffer.from(JSON.stringify(result, null, 2) + "\n");
if (out.length > 8388608) throw Error("EVALUATION_OUTPUT_BOUND");
writeFileSync(resolve(output), out, { flag: "wx" });
console.log(
  JSON.stringify({
    mode,
    sha256: createHash("sha256").update(out).digest("hex"),
    independentAcceptance: false,
    executionAuthority: "NONE"
  })
);
