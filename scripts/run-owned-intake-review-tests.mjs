import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, URL } from "node:url";
import { randomUUID, createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { snapshotWorktree } from "./worker-review-verifier.mjs";
if (process.platform !== "win32" || process.argv.slice(2).join(" ") !== "--confirm-owned-fixtures")
  throw Error("WINDOWS_OWNED_SYNTHETIC_FIXTURES_REQUIRE_EXPLICIT_TEST_COMMAND");
const repo = resolve(fileURLToPath(new URL("..", import.meta.url))),
  root = mkdtempSync(join(tmpdir(), "rc-oi-")),
  scratch = join(root, "scratch");
mkdirSync(scratch);
writeFileSync(join(root, "EVIDENCE_OWNERSHIP"), randomUUID(), { flag: "wx" });
const before = snapshotWorktree(repo),
  hash = (b) => createHash("sha256").update(b).digest("hex"),
  pins = before.members.map((path) => ({ path, sha256: hash(readFileSync(join(repo, path))) }));
writeFileSync(join(root, "SOURCE_HASHES.json"), JSON.stringify(pins, null, 2), { flag: "wx" });
const args = [
    join(repo, "node_modules/vitest/vitest.mjs"),
    "run",
    "--config",
    join(repo, "vitest.owned-intake.config.mjs"),
    "--configLoader",
    "native",
    "--reporter=default",
    "--reporter=json",
    "--outputFile=" + join(root, "vitest.json")
  ],
  started = Date.now(),
  child = spawn(process.execPath, args, {
    cwd: repo,
    windowsHide: true,
    env: {
      ...process.env,
      TEMP: scratch,
      TMP: scratch,
      TMPDIR: scratch,
      ROUTECAIRN_WORKER_LAB: root,
      TSX_DISABLE_CACHE: "1",
      NODE_DISABLE_COMPILE_CACHE: "1",
      GIT_OPTIONAL_LOCKS: "0"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
let stdout = "",
  stderr = "";
child.stdout.on("data", (b) => {
  stdout += b;
  process.stdout.write(b);
});
child.stderr.on("data", (b) => {
  stderr += b;
  process.stderr.write(b);
});
const code = await new Promise((r) => child.once("close", r));
const after = snapshotWorktree(repo),
  drift = pins.filter((p) => hash(readFileSync(join(repo, p.path))) !== p.sha256);
writeFileSync(join(root, "stdout.txt"), stdout, { flag: "wx" });
writeFileSync(join(root, "stderr.txt"), stderr, { flag: "wx" });
writeFileSync(
  join(root, "exit.json"),
  JSON.stringify(
    {
      code,
      elapsedMs: Date.now() - started,
      args,
      before,
      after,
      sourceDrift: drift,
      originalTestTimeoutMs: 30000,
      nativeReadinessMs: 20000,
      retainedRoot: root,
      evidenceDeleted: false,
      externalTargets: false,
      independentAcceptance: false
    },
    null,
    2
  ),
  { flag: "wx" }
);
console.log("RETAINED_OWNED_INTAKE_REVIEW_ROOT=" + root);
process.exitCode = code !== 0 || drift.length || JSON.stringify(before) !== JSON.stringify(after) ? 1 : 0;
