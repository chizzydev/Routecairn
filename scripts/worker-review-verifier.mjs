import fs from "node:fs";
import { resolve, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const fold = path => process.platform === "win32" ? path.toLowerCase() : path;
function paths(rows) {
  const seen = new Set();
  for (const p of rows) {
    if (typeof p !== "string" || !p || p.includes("\\") || p.startsWith("/") || p.split("/").some(v => !v || v === "." || v === "..") || /[\x00-\x1f\x7f:]/.test(p) || seen.has(p.toLowerCase())) throw Error("WORKTREE_PATH_REFUSED");
    seen.add(p.toLowerCase());
  }
  return [...rows].sort();
}
export function parseStatus(bytes) {
  const value = bytes.toString("utf8");
  if (!Buffer.from(value).equals(bytes) || value && !value.endsWith("\0")) throw Error("WORKTREE_STATUS_ENCODING");
  return value.split("\0").filter(Boolean).map(row => {
    // A review gate never accepts renamed, copied, deleted, conflicted or staged
    // source. NUL framing prevents quoting/newline ambiguities from hiding a path.
    const status = row.slice(0, 2), path = row.slice(3);
    if (row[2] !== " " || ![" M", "??"].includes(status)) throw Error("WORKTREE_STATUS_REFUSED");
    paths([path]); return { status, path };
  });
}
export function assertWorktreeMembership(expected, actual) {
  const normalize = rows => { paths(rows.map(r => r.path)); return rows.map(r => { if (![" M", "??"].includes(r.status)) throw Error("WORKTREE_STATUS_REFUSED"); return r.status + " " + r.path; }).sort(); };
  if (JSON.stringify(normalize(expected.status)) !== JSON.stringify(normalize(actual.status))) throw Error("WORKTREE_STATUS_MEMBERSHIP_MISMATCH");
  if (JSON.stringify(paths(expected.members)) !== JSON.stringify(paths(actual.members))) throw Error("WORKTREE_FILE_MEMBERSHIP_MISMATCH");
  if (expected.refs.length !== 3 || expected.refs.some(ref => ref !== "8192cda2b8475306ecbec215f7c3623d74af25ee")) throw Error("FROZEN_STAGE_C_REFERENCE_MISMATCH");
  if (JSON.stringify(expected.refs) !== JSON.stringify(actual.refs) || actual.index.length || expected.index.length) throw Error("GIT_REFERENCE_OR_INDEX_MISMATCH");
}
function git(repo, args) {
  return execFileSync("git", ["--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", ...args], { cwd: repo, windowsHide: true, maxBuffer: 32 * 1024 * 1024, env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" } });
}
export function snapshotWorktree(repo) {
  return { status: parseStatus(git(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"])), members: git(repo, ["ls-files", "--cached", "--others", "--exclude-standard", "-z"]).toString("utf8").split("\0").filter(Boolean), refs: git(repo, ["rev-parse", "HEAD", "main", "origin/main"]).toString("utf8").trim().split(/\r?\n/), index: git(repo, ["diff", "--cached", "--name-only", "-z"]).toString("utf8").split("\0").filter(Boolean) };
}
function ordinary(root, path) {
  paths([path]); const absolute = resolve(root, path), rel = relative(resolve(root), absolute);
  if (rel.startsWith(".." + sep) || rel === "..") throw Error("VERIFIER_ESCAPE");
  let parent = resolve(root); for (const part of path.split("/")) { parent = join(parent, part); const s = fs.lstatSync(parent); if (s.isSymbolicLink() || fold(fs.realpathSync.native(parent)) !== fold(parent)) throw Error("VERIFIER_ALIAS"); }
  const s = fs.lstatSync(absolute, { bigint: true }); if (!s.isFile() || s.nlink !== 1n) throw Error("VERIFIER_FILE_CUSTODY");
  return absolute;
}
function verifyReceipt(repo, row, native) {
  const path = ordinary(repo, row.path), before = fs.lstatSync(path, { bigint: true }), bytes = fs.readFileSync(path), after = fs.lstatSync(path, { bigint: true });
  if (digest(bytes) !== row.sha256 || ["dev", "ino", "nlink", "size", "mtimeNs", "ctimeNs"].some(k => String(before[k]) !== String(after[k]) || native && String(before[k]) !== row.identity[k])) throw Error("SOURCE_OR_NATIVE_IDENTITY_MISMATCH:" + row.path);
}
export function verifyWorkerReview(packet, repo) {
  packet = resolve(packet); repo = resolve(repo);
  const checksumRows = fs.readFileSync(ordinary(packet, "SHA256SUMS.txt"), "utf8").trimEnd().split("\n"), checksumPaths = [];
  for (const line of checksumRows) { const match = /^([a-f0-9]{64}) {2}(.+)$/.exec(line); if (!match) throw Error("CHECKSUM_FORMAT"); checksumPaths.push(match[2]); if (digest(fs.readFileSync(ordinary(packet, match[2]))) !== match[1]) throw Error("PACKET_MEMBER_MISMATCH:" + match[2]); }
  paths(checksumPaths);
  for (const required of ["WORKTREE.json", "WORKTREE_FILES.json", "SOURCE_HASHES.json", "PRESERVATION.json", "INCREMENT_ONLY_REVIEW.patch", "CUMULATIVE_STAGE_C_REVIEW.patch"]) if (!checksumPaths.includes(required)) throw Error("UNBOUND_REQUIRED_MEMBER");
  const read = p => JSON.parse(fs.readFileSync(ordinary(packet, p), "utf8")), expected = read("WORKTREE.json"), current = snapshotWorktree(repo);
  assertWorktreeMembership(expected, current);
  const sources = read("SOURCE_HASHES.json");
  if (JSON.stringify(paths(sources.map(r => r.path))) !== JSON.stringify(paths(expected.status.map(r => r.path)))) throw Error("SOURCE_SCOPE_MISMATCH");
  for (const row of sources) verifyReceipt(repo, row, true);
  const allFiles = read("WORKTREE_FILES.json");
  if (JSON.stringify(paths(allFiles.map(row => row.path))) !== JSON.stringify(paths(expected.members))) throw Error("WORKTREE_RECEIPT_MEMBERSHIP_MISMATCH");
  for (const row of allFiles) verifyReceipt(repo, row, true);
  const preservation = read("PRESERVATION.json"); for (const row of preservation.preservedReceipts) verifyReceipt(repo, row, true);
  // An unchanged Git status cannot conceal ignored generated-file drift: those
  // protected 1,277 artifacts have an exact independent inventory and receipts.
  const generated = [];
  const walk = (base, prefix) => { for (const name of fs.readdirSync(base)) { const path = join(base, name), s = fs.lstatSync(path); if (s.isSymbolicLink()) throw Error("GENERATED_ALIAS"); if (s.isDirectory()) walk(path, prefix + name + "/"); else if (s.isFile()) generated.push(prefix + name); else throw Error("GENERATED_SPECIAL_FILE"); } };
  for (const base of ["dist/", "apps/dashboard-ui/dist/"]) walk(join(repo, base), base);
  if (JSON.stringify(paths(generated)) !== JSON.stringify(paths(preservation.preservedReceipts.filter(r => r.path.startsWith("dist/") || r.path.startsWith("apps/dashboard-ui/dist/")).map(r => r.path)))) throw Error("GENERATED_MEMBERSHIP_MISMATCH");
  for (const name of ["INCREMENT_ONLY_REVIEW.patch", "CUMULATIVE_STAGE_C_REVIEW.patch"]) git(repo, ["apply", "--check", "--reverse", join(packet, name)]);
  assertWorktreeMembership(expected, snapshotWorktree(repo));
  return { readOnly: true, exactPendingPaths: current.status.length, exactNonignoredFiles: current.members.length, verifiedWorkingTreeFiles: allFiles.length, verifiedPacketMembers: checksumRows.length, protectedGeneratedFiles: generated.length, patchesReverseCheck: "PASS", operationalExecution: "HOLD", fullAcceptanceClaimed: false };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4) throw Error("Usage: node worker-review-verifier.mjs PACKET REPOSITORY");
  console.log(JSON.stringify(verifyWorkerReview(process.argv[2], process.argv[3])));
}
