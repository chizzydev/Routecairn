import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";

const roots = ["src", "apps/dashboard-ui/src"];
const maximumLines = 1800;

async function collect(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await collect(path));
    else if ([".ts", ".tsx"].includes(extname(entry.name))) result.push(path);
  }
  return result;
}

const violations = [];
for (const file of (await Promise.all(roots.map(collect))).flat()) {
  const relativePath = relative(process.cwd(), file).replaceAll("\\", "/");
  const lines = (await readFile(file, "utf8")).split(/\r?\n/u).length;
  const limit = maximumLines;
  if (lines > limit) violations.push(`${relativePath}: ${lines} lines (limit ${limit})`);
}
if (violations.length > 0) {
  process.stderr.write(`Module size budget exceeded:\n${violations.map((item) => ` - ${item}`).join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Module size budget passed (${maximumLines} line default ceiling).\n`);
}
