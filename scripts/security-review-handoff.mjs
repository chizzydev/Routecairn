import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";

const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();
if (git("status", "--porcelain")) throw new Error("Commit the complete candidate before preparing the review handoff.");
const sourceCommit = git("rev-parse", "HEAD");
const { version } = JSON.parse(await readFile("package.json", "utf8"));
const directory = resolve(".routecairn-release", `review-handoff-${sourceCommit}`);
await mkdir(directory, { recursive: true });
const filename = `routecairn-${version}-${sourceCommit}.zip`;
const path = join(directory, filename);
execFileSync("git", ["archive", "--format=zip", `--output=${path}`, sourceCommit]);
const bytes = await readFile(path);
const summary = {
  schemaVersion: 1, release: `v${version}`, sourceCommit, sourceTree: git("rev-parse", "HEAD^{tree}"),
  archive: filename, archiveSha256: createHash("sha256").update(bytes).digest("hex"), archiveBytes: bytes.length,
  independentReview: "NOT_PERFORMED", releaseStatus: "BLOCKED_PENDING_INDEPENDENT_REVIEW",
  instructions: "security-reviews/REVIEW-BRIEF.md", attestationSchema: "security-reviews/review.schema.json",
  trustRegistry: "security-reviews/trusted-reviewers.json", createdAt: new Date().toISOString()
};
await writeFile(join(directory, "handoff.json"), `${JSON.stringify(summary, null, 2)}\n`);
await writeFile(join(directory, "SHA256SUMS"), `${summary.archiveSha256}  ${filename}\n`);
process.stdout.write(`${directory}\n`);
