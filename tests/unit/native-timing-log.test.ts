import { it, expect } from "vitest";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createNativeTimingLog } from "../helpers/native-process-timing-log.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";

it("creates independent diagnostic identities for a reused PID without overwriting retained evidence", () => {
  const root = createOwnedTestDirectory("diagnostic-pid-reuse");
  try {
    writeFileSync(join(root, "EVIDENCE_OWNERSHIP"), "OWNED_SYNTHETIC_DIAGNOSTIC", { flag: "wx" });
    const first = createNativeTimingLog(root, 15588);
    appendFileSync(first, "retained-first-observation\n");
    const second = createNativeTimingLog(root, 15588);
    expect(second).not.toBe(first);
    expect(readFileSync(first, "utf8")).toBe("retained-first-observation\n");
    expect(readFileSync(second, "utf8")).toBe("");
  } finally {
    retainOwnedTestDirectory(root);
  }
});
