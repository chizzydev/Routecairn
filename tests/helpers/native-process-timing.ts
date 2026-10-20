import cp, { type ChildProcess } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { appendFileSync } from "node:fs";
import { afterAll } from "vitest";
import { createNativeTimingLog } from "./native-process-timing-log.js";
const root = process.env.ROUTECAIRN_WORKER_LAB;
if (!root) throw Error("OWNED_TIMING_ROOT_REQUIRED");
const output = createNativeTimingLog(root, process.pid);
const original = cp.fork;
cp.fork = ((...args: unknown[]) => {
  const child = (original as (...a: unknown[]) => ChildProcess)(...args);
  if (typeof args[0] === "string" && args[0].endsWith("bootstrap.mjs")) {
    const started = Date.now(),
      record = (event: string) =>
        appendFileSync(
          output,
          JSON.stringify({ pid: child.pid, event, at: new Date().toISOString(), elapsedMs: Date.now() - started }) +
            "\n"
        );
    record("FORK");
    child.on("message", (raw: unknown) => {
      const v = raw as { type?: unknown };
      if (
        v &&
        typeof v.type === "string" &&
        [
          "WORKER_BOOTSTRAP_READY",
          "WORKER_READY",
          "JOB_ACCEPTED",
          "JOB_PLAN",
          "JOB_COMPLETED",
          "JOB_FAILED",
          "JOB_CANCELLED",
          "WORKER_SHUTDOWN"
        ].includes(v.type)
      )
        record(v.type);
    });
    child.once("exit", () => record("ROOT_EXIT"));
  }
  return child;
}) as typeof cp.fork;
syncBuiltinESMExports();
const installed = cp.fork;
afterAll(() => {
  // Restore only our own instrumentation; never replace another test's export.
  if (cp.fork === installed) {
    cp.fork = original;
    syncBuiltinESMExports();
  }
});
