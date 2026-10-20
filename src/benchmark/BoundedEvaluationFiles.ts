import { lstatSync, openSync, fstatSync, readSync, closeSync } from "node:fs";
import { resolve, parse, join } from "node:path";
/** Ordinary read-only files, single link, stable identity, bounded bytes and no reparse ancestors. */
export function readEvaluationFile(path: string) {
  const p = resolve(path),
    root = parse(p).root,
    parts = p.slice(root.length).split(/[\\/]/).filter(Boolean),
    ancestors = parts.slice(0, -1).map((_, i) => join(root, ...parts.slice(0, i + 1))),
    before = ancestors.map((a) => {
      const s = lstatSync(a, { bigint: true });
      if (!s.isDirectory() || s.isSymbolicLink()) throw Error("EVALUATION_ORDINARY_ANCESTOR_REQUIRED");
      return s;
    });
  const s = lstatSync(p, { bigint: true });
  if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1n || s.size > 8388608n)
    throw Error("EVALUATION_BOUNDED_ORDINARY_FILE_REQUIRED");
  const fd = openSync(p, "r");
  try {
    const a = fstatSync(fd, { bigint: true });
    if (a.dev !== s.dev || a.ino !== s.ino || a.nlink !== 1n) throw Error("EVALUATION_FILE_IDENTITY_CHANGED");
    const buffer = Buffer.alloc(8388609);
    let length = 0;
    while (length < buffer.length) {
      const n = readSync(fd, buffer, length, buffer.length - length, null);
      if (n === 0) break;
      length += n;
    }
    const bytes = buffer.subarray(0, length),
      b = fstatSync(fd, { bigint: true }),
      c = lstatSync(p, { bigint: true });
    if (
      bytes.length > 8388608 ||
      [b, c].some(
        (x) =>
          x.dev !== a.dev ||
          x.ino !== a.ino ||
          x.size !== a.size ||
          x.mtimeNs !== a.mtimeNs ||
          x.ctimeNs !== a.ctimeNs ||
          x.nlink !== 1n ||
          x.isSymbolicLink()
      )
    )
      throw Error("EVALUATION_FILE_CHANGED");
    for (let i = 0; i < ancestors.length; i++) {
      const x = lstatSync(ancestors[i]!, { bigint: true }),
        v = before[i]!;
      if (!x.isDirectory() || x.isSymbolicLink() || x.dev !== v.dev || x.ino !== v.ino)
        throw Error("EVALUATION_ANCESTOR_CHANGED");
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}
export function evidenceRelativePath(root: string, path: string) {
  if (!/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(path) || path.split("/").some((p) => p === "." || p === ".."))
    throw Error("EVALUATION_SAFE_RELATIVE_PATH_REQUIRED");
  return join(resolve(root), ...path.split("/"));
}
