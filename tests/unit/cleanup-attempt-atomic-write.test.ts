import { afterEach, describe, expect, it, vi } from "vitest";
import { writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
import { durableAtomicWrite } from "../../src/core/offensive/MutationJournal.js";
const state = vi.hoisted(() => ({
  hook: undefined as undefined | ((source: string, destination: string) => Promise<void>),
  calls: 0
}));
vi.mock("node:fs/promises", async (original) => {
  const real = await original<typeof import("node:fs/promises")>();
  return {
    ...real,
    rename: async (a: string, b: string) => {
      state.calls++;
      await state.hook?.(a, b);
      return real.rename(a, b);
    }
  };
});
const roots: string[] = [];
async function fixture() {
  const root = createOwnedTestDirectory("bounded-native-atomic-replacement");
  roots.push(root);
  const path = join(root, "checkpoint.enc");
  await writeFile(path, "original");
  return { root, path };
}
const denied = () => Object.assign(Error("Fixture Windows sharing violation"), { code: "EPERM" });
afterEach(() => {
  state.hook = undefined;
  state.calls = 0;
  for (const root of roots.splice(0)) retainOwnedTestDirectory(root);
});
describe.skipIf(process.platform !== "win32")("bounded cleanup evidence atomic replacement", () => {
  it("retries a transient sharing violation without changing the replacement authority", async () => {
    const f = await fixture();
    state.hook = async () => {
      if (state.calls === 1) throw denied();
    };
    await durableAtomicWrite(f.path, "replacement");
    expect(await readFile(f.path, "utf8")).toBe("replacement");
    expect(state.calls).toBe(2);
  });
  it("bounds persistent denial and retains the old and prepared evidence", async () => {
    const f = await fixture();
    let source = "";
    state.hook = async (a) => {
      source = a;
      throw denied();
    };
    await expect(durableAtomicWrite(f.path, "replacement")).rejects.toThrow();
    expect(state.calls).toBe(6);
    expect(await readFile(f.path, "utf8")).toBe("original");
    expect(await readFile(source, "utf8")).toBe("replacement");
  });
  it("refuses replacement after destination identity changes during denial", async () => {
    const f = await fixture();
    state.hook = async (_a, b) => {
      if (state.calls === 1) {
        await writeFile(join(f.root, "incoming"), "unrelated");
        const real = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
        await real.rename(b, join(f.root, "retained-original"));
        await real.rename(join(f.root, "incoming"), b);
        throw denied();
      }
    };
    await expect(durableAtomicWrite(f.path, "replacement")).rejects.toThrow("ATOMIC_REPLACEMENT_IDENTITY_CHANGED");
    expect(state.calls).toBe(1);
    expect(await readFile(f.path, "utf8")).toBe("unrelated");
    expect(await readFile(join(f.root, "retained-original"), "utf8")).toBe("original");
  });
  it("refuses a changed prepared file before retrying", async () => {
    const f = await fixture();
    state.hook = async (a) => {
      await writeFile(a, "altered prepared evidence");
      throw denied();
    };
    await expect(durableAtomicWrite(f.path, "replacement")).rejects.toThrow("ATOMIC_REPLACEMENT_IDENTITY_CHANGED");
    expect(state.calls).toBe(1);
    expect(await readFile(f.path, "utf8")).toBe("original");
  });
  it("does not retry a non-sharing failure", async () => {
    const f = await fixture();
    state.hook = async () => {
      throw Object.assign(Error("FIXTURE_IO_FAILURE"), { code: "EIO" });
    };
    await expect(durableAtomicWrite(f.path, "replacement")).rejects.toThrow("FIXTURE_IO_FAILURE");
    expect(state.calls).toBe(1);
    expect(await readFile(f.path, "utf8")).toBe("original");
  });
});
