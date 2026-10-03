import { lstat, realpath, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = await realpath(resolve(dirname(fileURLToPath(import.meta.url)), ".."));
const output = resolve(root, "dist");
if (output !== join(root, "dist") || dirname(output) !== root) throw new Error("Release output is outside the repository.");
const stat = await lstat(output).catch((error) => { if (error.code === "ENOENT") return undefined; throw error; });
if (stat) {
  if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(output) !== output) throw new Error("Release output must be the repository's real generated directory.");
  await rm(output, { recursive: true, force: false });
}
process.stdout.write("Cleared verified generated release output.\n");
