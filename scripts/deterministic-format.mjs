import { readdir, readFile, writeFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";

const write = process.argv.includes("--write");
const check = process.argv.includes("--check");
if (write === check) throw new Error("Use exactly one of --write or --check.");

const roots = ["src", "tests", "apps", "scripts", "docs", ".github", "deploy"];
const rootFiles = ["README.md", "SECURITY.md", "CHANGELOG.md", "package.json", "tsconfig.json", "vitest.config.ts", "eslint.config.mjs", "stryker.config.mjs"];
const extensions = new Set([".ts", ".tsx", ".mjs", ".json", ".md", ".yml", ".yaml", ".css", ".html"]);
const ignored = new Set(["node_modules", "dist", ".git", ".routecairn-coverage", ".stryker-tmp", "reports"]);

async function filesUnder(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true }).catch(() => [])) {
    if (ignored.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await filesUnder(path));
    else if (extensions.has(extname(entry.name)) && entry.name !== "package-lock.json") result.push(path);
  }
  return result;
}

const files = [...new Set([...(await Promise.all(roots.map(filesUnder))).flat(), ...rootFiles])].sort();
const changed = [];
for (const file of files) {
  const original = await readFile(file, "utf8").catch(() => undefined);
  if (original === undefined) continue;
  const normalized = `${original.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").split("\n").map((line) => line.replace(/[ \t]+$/u, "")).join("\n").replace(/\n*$/u, "")}\n`;
  if (normalized === original) continue;
  changed.push(relative(process.cwd(), file).replaceAll("\\", "/"));
  if (write) await writeFile(file, normalized, "utf8");
}

if (changed.length > 0 && check) {
  process.stderr.write(`Files are not deterministically formatted:\n${changed.map((file) => ` - ${file}`).join("\n")}\nRun npm run format.\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(write ? `Formatted ${changed.length} file(s).\n` : `Checked ${files.length} file(s).\n`);
}
