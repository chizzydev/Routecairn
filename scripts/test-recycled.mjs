import { mkdir, readdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { resolve } from "node:path";

const coverage = process.argv.includes("--coverage");
const runId = `${Date.now()}-${process.pid}`;
const output = resolve(".routecairn-engineering-lab", "test-runs", runId);
await mkdir(output, { recursive: true });
const cli = resolve("node_modules/vitest/vitest.mjs");
const count = 4;
const source = await snapshot();
for (let shard = 1; shard <= count; shard++) {
  if (await snapshot() !== source) throw new Error("Source changed during the suite; restart verification.");
  await run(["run", "--config", "vitest.shard.config.ts", `--shard=${shard}/${count}`, "--pool=forks", "--maxWorkers=1", "--reporter=default", "--reporter=blob", `--outputFile.blob=${output}/shard-${shard}.blob.json`, ...(coverage ? ["--coverage", `--coverage.reportsDirectory=${output}/coverage-${shard}`] : [])]);
}
if (await snapshot() !== source) throw new Error("Source changed during the suite; partial results are not accepted.");
await run(["--merge-reports", output, "--reporter=default", "--reporter=json", `--outputFile.json=${output}/results.json`, ...(coverage ? ["--coverage"] : [])]);
process.stdout.write(`Recycled suite evidence: ${output}/results.json\n`);

function run(args) {
  return new Promise((accept, reject) => {
    const child = spawn(process.execPath, ["--max-old-space-size=4096", cli, ...args], { stdio: "inherit", env: { ...process.env } });
    child.once("error", reject);
    child.once("exit", (code, signal) => code === 0 ? accept() : reject(new Error(`Test process failed: ${code ?? signal}. No partial result is accepted.`)));
  });
}

async function snapshot() {
  const files = [];
  for (const root of ["src", "tests", "apps/dashboard-ui/src", "scripts"]) {
    for (const file of await readdir(root, { recursive: true })) if (/\.(?:ts|tsx|mjs|json|py|go)$/u.test(file)) files.push(`${root}/${file}`.replaceAll("\\", "/"));
  }
  files.push("package.json", "package-lock.json", "vitest.config.ts", "vitest.shard.config.ts");
  const digest = createHash("sha256");
  for (const file of files.sort()) digest.update(file).update("\0").update(await readFile(file)).update("\0");
  return digest.digest("hex");
}
