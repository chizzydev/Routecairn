import { copyFile, readFile } from "node:fs/promises";

const mode = process.argv[2];
if (mode === "--from-shrinkwrap") await copyFile("npm-shrinkwrap.json", "package-lock.json");
else if (mode === "--write") await copyFile("package-lock.json", "npm-shrinkwrap.json");
else if (mode !== "--check") throw new Error("Use --check, --write or --from-shrinkwrap.");
const lock = JSON.parse(await readFile("package-lock.json", "utf8"));
const published = JSON.parse(await readFile("npm-shrinkwrap.json", "utf8"));
if (JSON.stringify(lock) !== JSON.stringify(published)) throw new Error("Published runtime shrinkwrap differs from the reviewed dependency lockfile.");
process.stdout.write("Reviewed and published dependency graphs match.\n");
