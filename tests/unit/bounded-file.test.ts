import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { loadOrCreateHexKey, readBoundedFile, readBoundedFileSync } from "../../src/dashboard/security/BoundedFile.js";

describe("bounded opened-file reads and persistent keys", () => {
  it("enforces exact byte limits for synchronous and asynchronous readers", async () => {
    const directory = mkdtempSync(join(tmpdir(), "routecairn-bounded-"));
    try {
      const file = join(directory, "data"); writeFileSync(file, "four");
      expect(readBoundedFileSync(file, 4).toString()).toBe("four");
      expect((await readBoundedFile(file, 4)).toString()).toBe("four");
      expect(() => readBoundedFileSync(file, 3)).toThrow(/limit/);
      await expect(readBoundedFile(file, 3)).rejects.toThrow(/limit/);
      expect(() => readBoundedFileSync(file, -1)).toThrow(/Invalid/);
      expect(() => readBoundedFileSync(directory, 16)).toThrow();
      writeFileSync(file, ""); expect(readBoundedFileSync(file, 0).length).toBe(0);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
  it("retains existing keys and rejects corrupt keys without replacing them", () => {
    const directory = mkdtempSync(join(tmpdir(), "routecairn-key-"));
    try {
      const path = join(directory, "nested", "key"); const key = loadOrCreateHexKey(path);
      expect(key.length).toBe(32); expect(loadOrCreateHexKey(path).equals(key)).toBe(true);
      writeFileSync(path, "corrupt"); expect(() => loadOrCreateHexKey(path)).toThrow(/canonical/);
      expect(readFileSync(path, "utf8")).toBe("corrupt");
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
});
