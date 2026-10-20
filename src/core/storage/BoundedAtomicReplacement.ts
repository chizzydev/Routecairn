import { lstat, rename } from "node:fs/promises";
import type { BigIntStats } from "node:fs";
import { dirname } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
async function snapshot(path: string, directory = false): Promise<BigIntStats | undefined> {
  try {
    const value = await lstat(path, { bigint: true });
    if (value.isSymbolicLink() || (directory ? !value.isDirectory() : !value.isFile() || value.nlink !== 1n))
      throw Error("ATOMIC_REPLACEMENT_IDENTITY_CHANGED");
    return value;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}
const same = (a: BigIntStats | undefined, b: BigIntStats | undefined, directory = false) =>
  !a || !b
    ? a === b
    : (directory ? (["dev", "ino"] as const) : (["dev", "ino", "nlink", "size", "mtimeNs", "ctimeNs"] as const)).every(
        (k) => a[k] === b[k]
      );
/** Retry only the same prepared atomic replacement after a Windows sharing denial.
 * No delete/chmod fallback, target adoption, new payload or network replay. All
 * prepared evidence remains if either identity changes or the fixed bound expires. */
export async function boundedAtomicReplacement(source: string, destination: string): Promise<void> {
  if (process.platform !== "win32") return rename(source, destination);
  const prepared = await snapshot(source),
    prior = await snapshot(destination),
    parent = dirname(destination),
    parentIdentity = await snapshot(parent, true);
  if (!prepared || !parentIdentity) throw Error("ATOMIC_REPLACEMENT_IDENTITY_CHANGED");
  for (let attempt = 0; ; attempt++) {
    try {
      await rename(source, destination);
      return;
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error ? error.code : undefined;
      if (!["EPERM", "EACCES", "EBUSY"].includes(String(code)) || attempt >= 5) throw error;
      await delay(10 * 2 ** attempt);
      if (
        !same(prepared, await snapshot(source)) ||
        !same(prior, await snapshot(destination)) ||
        !same(parentIdentity, await snapshot(parent, true), true)
      )
        throw Error("ATOMIC_REPLACEMENT_IDENTITY_CHANGED");
    }
  }
}
