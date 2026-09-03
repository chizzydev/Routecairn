import { realpathSync } from "node:fs";
import { basename, isAbsolute, relative, resolve } from "node:path";

/** Validate canonical containment on the owning OS, including Windows paths and symlinks. */
export function resolveRecoveryBundlePath(journalDirectory: string, bundlePath: string, caseId: string): string {
  if (!isAbsolute(bundlePath) || bundlePath.split(/[\\/]/).includes("..") || basename(bundlePath) !== `${caseId}.recovery.enc`) throw new Error("RECOVERY_PATH_INVALID");
  const root = realpathSync(resolve(journalDirectory));
  const canonical = realpathSync(bundlePath);
  const inside = relative(root, canonical);
  if (!inside || isAbsolute(inside) || inside.split(/[\\/]/).includes("..")) throw new Error("RECOVERY_PATH_INVALID");
  return canonical;
}
