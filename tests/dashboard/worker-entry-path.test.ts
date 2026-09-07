import { existsSync } from "node:fs";
import { isAbsolute, basename } from "node:path";
import { describe, expect, it } from "vitest";
import { workerEntryPath } from "../../src/dashboard/worker/ScanWorkerManager.js";

describe("dashboard worker entry resolution", () => {
  it("resolves beside the loaded manager instead of depending on the caller working directory", () => {
    const entry = workerEntryPath();

    expect(isAbsolute(entry)).toBe(true);
    expect(existsSync(entry)).toBe(true);
    expect(basename(entry)).toMatch(/^ScanWorkerMain\.(?:ts|js)$/);
  });
});
