import cp, { type ChildProcess } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { createNativeTimingLog } from "./native-process-timing-log.js";
import { afterAll } from "vitest";
const root = process.env.ROUTECAIRN_WORKER_LAB;
if (!root) throw Error("OWNED_STAGE_TIMING_REQUIRED");
const nativeLog = createNativeTimingLog(root, process.pid);
const original = cp.fork,
  output = join(root, "BOUNDARY_STAGES_" + process.pid + ".jsonl");
cp.fork = ((...args: unknown[]) => {
  const child = (original as (...a: unknown[]) => ChildProcess)(...args);
  if (typeof args[0] !== "string" || !args[0].endsWith("bootstrap.mjs")) return child;
  const start = Date.now(),
    record = (event: string) =>
      appendFileSync(
        output,
        JSON.stringify({ pid: child.pid, event, at: Date.now(), elapsedMs: Date.now() - start }) + "\n"
      );
  record("FORK");
  const nativeRecord = (event: string) =>
    appendFileSync(
      nativeLog,
      JSON.stringify({ pid: child.pid, event, at: new Date().toISOString(), elapsedMs: Date.now() - start }) + "\n"
    );
  nativeRecord("FORK");
  const send = child.send.bind(child);
  child.send = ((...values: unknown[]) => {
    const m = values[0] as { type?: string };
    if (["IDENTIFY_PROCESS", "ACTIVATE_RUNTIME", "INITIALIZE_JOB", "RUN_JOB", "SHUTDOWN"].includes(m?.type ?? ""))
      record("SEND_" + m.type);
    return Reflect.apply(send, child, values);
  }) as typeof child.send;
  child.on("message", (raw) => {
    const m = raw as { type?: string };
    if (
      [
        "WORKER_BOOTSTRAP_READY",
        "WORKER_IDENTITY_CONFIRMED",
        "WORKER_READY",
        "JOB_ACCEPTED",
        "JOB_PLAN",
        "JOB_COMPLETED",
        "JOB_FAILED",
        "JOB_CANCELLED",
        "WORKER_SHUTDOWN"
      ].includes(m?.type ?? "")
    ) {
      record("RECV_" + m.type);
      nativeRecord(m.type!);
    }
  });
  child.once("exit", () => {
    record("ROOT_EXIT");
    nativeRecord("ROOT_EXIT");
  });
  return child;
}) as typeof cp.fork;
syncBuiltinESMExports();
const installed = cp.fork;
afterAll(() => {
  if (cp.fork === installed) {
    cp.fork = original;
    syncBuiltinESMExports();
  }
});
