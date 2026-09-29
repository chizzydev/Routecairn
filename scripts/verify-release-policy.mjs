import { readFile } from "node:fs/promises";

const packageJson = JSON.parse(await readFile("package.json", "utf8"));
const lock = JSON.parse(await readFile("package-lock.json", "utf8"));
const changelog = await readFile("CHANGELOG.md", "utf8");
const compatibility = await readFile("docs/COMPATIBILITY.md", "utf8");
const tagIndex = process.argv.indexOf("--tag");
const requestedTag = (tagIndex >= 0 ? process.argv[tagIndex + 1] : undefined) || process.env.GITHUB_REF_NAME;
const expectedTag = `v${packageJson.version}`;

if (lock.version !== packageJson.version || lock.packages?.[""]?.version !== packageJson.version) throw new Error("package.json and package-lock.json versions differ.");
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(packageJson.version)) throw new Error("Package version is not valid Semantic Versioning.");
if (!changelog.includes(`## [${packageJson.version}]`)) throw new Error(`CHANGELOG.md has no ${packageJson.version} release entry.`);
if (!compatibility.includes("Semantic Versioning") || !compatibility.includes("Versioned contracts")) throw new Error("Compatibility policy is incomplete.");
if (requestedTag && requestedTag !== expectedTag) throw new Error(`Tag ${requestedTag} does not match package version ${expectedTag}.`);
process.stdout.write(`Release policy verified for ${expectedTag}.\n`);
