import { randomUUID } from "node:crypto";
import { lstatSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** Diagnostic identity only. A reused PID never authorizes adoption of an earlier log. */
export function createNativeTimingLog(root: string, pid: number): string {
  const marker = lstatSync(join(root, "EVIDENCE_OWNERSHIP"));
  if (!marker.isFile() || marker.isSymbolicLink() || marker.nlink !== 1 || !Number.isSafeInteger(pid) || pid < 1)
    throw Error("OWNED_TIMING_ROOT_REQUIRED");
  const output = join(root, `native-process-timings-${pid}-${randomUUID()}.jsonl`);
  writeFileSync(output, "", { flag: "wx" });
  return output;
}
