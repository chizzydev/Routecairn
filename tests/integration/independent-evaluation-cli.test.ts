import { it, expect } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, existsSync, linkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { witnessFixture } from "../helpers/evaluation-witness-fixture.js";
import { readEvaluationFile, evidenceRelativePath } from "../../src/benchmark/BoundedEvaluationFiles.js";
it("executes public evidence seal and signed score without reading labels early or overwriting outputs", () => {
  const root = mkdtempSync(join(tmpdir(), "rc-evaluation-cli-")),
    f = witnessFixture(),
    json = (name: string, value: unknown) => {
      const p = join(root, name);
      writeFileSync(p, JSON.stringify(value), { flag: "wx" });
      return p;
    };
  writeFileSync(join(root, "EVIDENCE_OWNERSHIP"), "Same-author isolated CLI protocol test; retained");
  const manifest = json("manifest.json", f.study),
    expected = createHash("sha256").update(readFileSync(manifest)).digest("hex");
  json("enrollment.json", f.enrollment);
  json("sealed.json", f.seal);
  json("catalog.json", f.catalog);
  json("release.json", f.release);
  mkdirSync(join(root, "reports"));
  for (const [path, bytes] of f.files) writeFileSync(join(root, "reports", path), bytes, { flag: "wx" });
  writeFileSync(join(root, "public.pem"), f.pem);
  writeFileSync(join(root, "signature.txt"), f.signature);
  writeFileSync(join(root, "oracle.json"), f.oracle);
  writeFileSync(join(root, "bad-signature.txt"), "bad");
  const receipts: unknown[] = [],
    run = (mode: string, args: string[]) => {
      const command = [
          "--import",
          "tsx",
          "scripts/independent-evaluation-intake.ts",
          mode,
          manifest,
          expected,
          ...args.map((a) => join(root, a))
        ],
        r = spawnSync(process.execPath, command, {
          cwd: process.cwd(),
          encoding: "utf8",
          windowsHide: true,
          env: { ...process.env, TSX_DISABLE_CACHE: "1" }
        });
      receipts.push({ command, status: r.status, stdout: r.stdout, stderr: r.stderr });
      return r;
    };
  expect(
    run("seal-evidence", ["enrollment.json", "sealed.json", "catalog.json", "reports", "witness.json"]).status
  ).toBe(0);
  expect(existsSync(join(root, "witness.json"))).toBe(true);
  expect(
    run("score-evidence", [
      "sealed.json",
      "release.json",
      "public.pem",
      "witness.json",
      "signature.txt",
      "oracle.json",
      "score.json"
    ]).status
  ).toBe(0);
  const score = JSON.parse(readFileSync(join(root, "score.json"), "utf8"));
  expect(score.knownVulnerabilities.missed).toBe(4);
  expect(score.independentAcceptance).toBe(false);
  expect(
    run("seal-evidence", ["enrollment.json", "sealed.json", "catalog.json", "reports", "witness.json"]).status
  ).not.toBe(0);
  const rejected = run("score-evidence", [
    "sealed.json",
    "release.json",
    "public.pem",
    "witness.json",
    "bad-signature.txt",
    "NEVER_OPEN_PRIVATE_ORACLE",
    "bad-score.json"
  ]);
  expect(rejected.status).not.toBe(0);
  expect(rejected.stderr).toContain("WITNESS_RELEASE_SIGNATURE");
  expect(rejected.stderr).not.toContain("ENOENT");
  expect(existsSync(join(root, "bad-score.json"))).toBe(false);
  const single = join(root, "single.txt"),
    alias = join(root, "alias.txt");
  writeFileSync(single, "owned");
  linkSync(single, alias);
  expect(() => readEvaluationFile(single)).toThrow("ORDINARY");
  expect(() => evidenceRelativePath(root, "../oracle.json")).toThrow("RELATIVE");
  writeFileSync(
    join(root, "CLI_RECEIPTS.json"),
    JSON.stringify({ receipts, score, root, independentAcceptance: false }, null, 2),
    { flag: "wx" }
  );
});
