import { it, expect } from "vitest";
import { mkdirSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { GlobalMutationLock } from "../../src/core/offensive/MutationJournal.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
it.skipIf(process.platform !== "win32")(
  "refuses an unsupported native coordination path before creating an ambiguous database",
  async () => {
    const root = createOwnedTestDirectory("sqlite-path-budget"),
      base = join(root, "path");
    mkdirSync(base);
    const suffix = ".coordination.sqlite",
      n = 254 - base.length - 1 - suffix.length,
      lock = join(base, "x".repeat(n)),
      db = lock + suffix;
    expect(db.length).toBe(254);
    expect(existsSync(db)).toBe(false);
    let error: unknown;
    try {
      await new GlobalMutationLock(lock).acquire("owned-path-probe", true);
    } catch (e) {
      error = e;
    }
    writeFileSync(
      join(root, "NATIVE_COORDINATION_PATH_RECEIPT.json"),
      JSON.stringify({
        path: db,
        pathLength: db.length,
        existsAfter: existsSync(db),
        error: String(error),
        nativeOnlyFixture: true
      }),
      { flag: "wx" }
    );
    try {
      expect(String(error)).toContain("SQLITE_NATIVE_PATH_BUDGET_EXCEEDED");
      expect(existsSync(db)).toBe(false);
    } finally {
      retainOwnedTestDirectory(root);
    }
  }
);
