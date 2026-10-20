import { resolve } from "node:path";
/** Conservative default Windows SQLite VFS envelope, including the native rollback
 * journal suffix and NUL. Node filesystem long-path support does not establish
 * native SQLite journal support. Refuse before opening; never relocate/adopt data. */
export function assertSqliteNativePath(path: string): void {
  if (process.platform !== "win32" || path === ":memory:") return;
  if (resolve(path).length > 250)
    throw Error(
      "SQLITE_NATIVE_PATH_BUDGET_EXCEEDED: choose a shorter new owned data directory; existing data is never moved or removed."
    );
}
