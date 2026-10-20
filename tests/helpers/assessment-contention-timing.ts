import { afterAll } from "vitest";
import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { freemem, totalmem } from "node:os";
import { performance } from "node:perf_hooks";
const root = process.env.ROUTECAIRN_WORKER_LAB;
if (!root) throw Error("OWNED_TIMING_ROOT_REQUIRED");
const file = join(root, "SCHEDULER_" + process.pid + ".jsonl");
let prior = performance.now();
const sample = (stage: string) => {
  const now = performance.now();
  appendFileSync(
    file,
    JSON.stringify({
      stage,
      pid: process.pid,
      parent: process.ppid,
      wallMs: Date.now(),
      monotonicMs: now,
      sampleGapMs: now - prior,
      cpu: process.cpuUsage(),
      memory: process.memoryUsage(),
      hostFreeBytes: freemem(),
      hostTotalBytes: totalmem(),
      meaning: "OBSERVATIONAL_NOT_CAUSAL_PROOF"
    }) + "\n"
  );
  prior = now;
};
sample("BEGIN");
const timer = setInterval(() => sample("SAMPLE"), 1000);
timer.unref();
afterAll(() => {
  clearInterval(timer);
  sample("END");
});
