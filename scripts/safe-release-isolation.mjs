import { createHash, randomUUID } from "node:crypto";
import { constants, openSync, closeSync, fstatSync, lstatSync, realpathSync, readSync, writeSync, opendirSync, mkdirSync, mkdtempSync, unlinkSync, rmdirSync, statfsSync } from "node:fs";
import { dirname, join, resolve, relative, isAbsolute, sep } from "node:path";

// Review tooling only. No subprocess, network, npm, release or owner-copy API.
export const PIN = "8192cda2b8475306ecbec215f7c3623d74af25ee";
export const SOURCE_DIGEST = "9948359bc6137ad7a7018560817f14aff40ed8c50539dbe195de0e28d122082d";
export const DESIGN_MANIFEST_DIGEST = "4af3eaddcc6acf7a7c788e8b8e7e6f4306a0e2820c5c9c09ba2a99805624c9f8";
export const ORIGINAL_REVIEW_DIGEST = "57cb87afe6b090581ae62cf4c86bf0631f752abc8740a68f359afeb525f1cfd6";
export const A1_PATHS = Object.freeze(["scripts/safe-release-preflight.mjs", "scripts/safe-release-isolation.mjs", "tests/unit/safe-release-isolation.test.ts", "docs/SAFE_RELEASE_ISOLATION.md"]);
export const LIMITS = Object.freeze({ sourceFiles: 1500, sourceBytes: 256 * 1024 ** 2, inputBytes: 32 * 1024 ** 2, candidateFiles: 999, candidateBytes: 8 * 1024 ** 2 - 1, cleanupEntries: 512, cleanupBytes: 64 * 1024 ** 2, cleanupDepth: 12, outputBytes: 2 * 1024 ** 2, freeBytes: 2 * 1024 ** 3, processMs: 30_000, processRssBytes: 512 * 1024 ** 2, stdioBytes: 2 * 1024 ** 2 });
const deny = (code) => { throw new Error("A1_" + code); };
export const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
export function portablePath(name) {
  if (typeof name !== "string" || name.length < 1 || name.length > 240 || !/^[A-Za-z0-9_.\/-]+$/.test(name) || name.startsWith("/") || name.includes("\\")) deny("PATH");
  for (const part of name.split("/")) {
    if (!part || part === "." || part === ".." || /[. ]$/.test(part) || /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part) || [".git", ".npmrc"].includes(part.toLowerCase())) deny("PATH");
  }
  return name;
}
export function exactNames(actual, expected) {
  function normalized(values) {
    if (!Array.isArray(values) || values.length > 5000) deny("PATH_SET");
    const seen = new Set();
    for (const name of values) { portablePath(name); const key = name.toLowerCase(); if (seen.has(key)) deny("PATH_COLLISION"); seen.add(key); }
    return [...values].sort();
  }
  if (JSON.stringify(normalized(actual)) !== JSON.stringify(normalized(expected))) deny("PATH_SET");
}
export function validateEntries(entries, kind = "source") {
  const maximum = kind === "candidate" ? LIMITS.candidateFiles : LIMITS.sourceFiles;
  const cap = kind === "candidate" ? LIMITS.candidateBytes : LIMITS.sourceBytes;
  if (!Array.isArray(entries) || !entries.length || entries.length > maximum) deny("FILE_CAP");
  exactNames(entries.map((v) => v.path), entries.map((v) => v.path)); let total = 0;
  for (const entry of entries) {
    if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || entry.bytes > LIMITS.inputBytes || !/^[a-f0-9]{64}$/.test(entry.sha256)) deny("ENTRY");
    total += entry.bytes; if (total > cap) deny("BYTE_CAP");
  }
  return total;
}
// Matches the frozen design's canonical digest, with locale-independent order.
export function manifestDigest(entries) {
  validateEntries(entries);
  return digest(JSON.stringify(entries.map(({ path, sha256, bytes }) => ({ path, sha256, bytes })).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)));
}
export function assertGitState(state, changed, sourcePaths) {
  for (const key of ["head", "main", "originMain"]) if (state[key] !== PIN) deny("GIT_PIN");
  if (state.remoteMain !== undefined && state.remoteMain !== PIN) deny("GIT_PIN");
  if (state.index.length) deny("INDEX");
  exactNames(state.status.map((v) => v.path), changed.map((v) => v.path));
  const allowed = new Map(changed.map((v) => [v.path, v.status]));
  for (const item of state.status) if (allowed.get(item.path) !== item.status) deny("STATUS");
  exactNames([...state.tracked, ...changed.filter((v) => v.status === "??").map((v) => v.path)], sourcePaths);
  return { liveRemote: state.remoteMain === PIN ? "SUPPLIED_PIN_MATCHES" : "HOLD_NO_NETWORK_IN_READONLY_MODE" };
}
export function dependencyClosure(files, roots, edges) {
  const names = new Set(files); exactNames(files, files); const adjacency = new Map();
  for (const edge of edges) {
    portablePath(edge.from); portablePath(edge.to);
    if (!names.has(edge.from) || !names.has(edge.to)) deny("CLOSURE_MISSING");
    const items = adjacency.get(edge.from) || []; items.push(edge.to); adjacency.set(edge.from, items);
  }
  const visited = new Set(), queue = [...roots];
  for (let i = 0; i < queue.length; i++) {
    const name = queue[i]; if (!names.has(name)) deny("CLOSURE_MISSING");
    if (visited.has(name)) continue; visited.add(name); queue.push(...(adjacency.get(name) || []));
  }
  return { status: "STATIC_EDGES_VERIFIED", roots: [...roots].sort(), reached: [...visited].sort(), edges: edges.length, runtimeClosure: "HOLD_SEPARATE_NATIVE_AND_LIFECYCLE_REVIEW" };
}
export function packagePath(name, allowlist) {
  portablePath(name);
  if (/^(?:src|tests?|scripts|acceptance|security-reviews|private|operator|backups?|reports?|\.routecairn)(?:\/|$)/i.test(name) || /(?:\.map$|\.(?:key|pem|db|sqlite3?|bak|env)$|(?:^|\/)(?:witness|session|token|credential|history|owner-result|native-wire|outcome-wire)[^/]*\.(?:jsonl?|txt|log)$|\.fixture\.[cm]?[jt]s$)/i.test(name)) deny("PACKAGE_PRIVATE_PATH");
  if (name.endsWith(".d.ts") && name !== "dist/core/plugins/ModuleSdk.d.ts") deny("PACKAGE_DECLARATION");
  if (!allowlist.some((glob) => matchesGlob(name, glob))) deny("PACKAGE_ALLOWLIST");
  return name;
}
export function matchesGlob(name, glob) {
  portablePath(name);
  if (typeof glob !== "string" || !/^[A-Za-z0-9_.\/*-]+$/.test(glob)) deny("GLOB");
  portablePath(glob.replaceAll("*", "x"));
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("**/", "\u0001").replaceAll("**", "\u0002").replaceAll("*", "[^/]*").replaceAll("\u0001", "(?:.*/)?").replaceAll("\u0002", ".*");
  return new RegExp("^" + escaped + "$", "u").test(name);
}
export function auditCandidate(entries, allowlist) {
  validateEntries(entries, "candidate");
  for (const item of entries) {
    packagePath(item.path, allowlist);
    if (!Buffer.isBuffer(item.content) || item.content.length !== item.bytes || digest(item.content) !== item.sha256) deny("PACKAGE_BYTES");
    if (/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|function\s+provisionFixtureWitness\s*\(|FIXTURE_WITNESS_ALREADY_BOUND|ROUTECAIRN_STAGE_B_WIRE_EVIDENCE|PACKAGE_PRIVATE_CANARY_[a-z0-9]{16}/.test(item.content.toString("utf8"))) deny("PACKAGE_PRIVATE_CONTENT");
  }
  return { files: entries.length, bytes: entries.reduce((s, v) => s + v.bytes, 0), arbitrarySecretAbsence: "NOT_PROVEN", installedPackage: false, internalExecuteFreshConflict: "HOLD" };
}
export function resourcePlan({ sourceBytes, dependencyBytes, freeBytes }) {
  for (const value of [sourceBytes, dependencyBytes, freeBytes]) if (!Number.isSafeInteger(value) || value < 0) deny("RESOURCE_ESTIMATE");
  if (sourceBytes > LIMITS.sourceBytes) deny("BYTE_CAP");
  // Input, build, consumer, archive, logs + three dependency/native build copies,
  // with 50% margin. Estimates are supplied for review, never install consent.
  const peakBytes = Math.ceil((sourceBytes * 3 + dependencyBytes * 3 + LIMITS.candidateBytes * 2 + LIMITS.stdioBytes * 2) * 1.5) + LIMITS.freeBytes;
  if (!Number.isSafeInteger(peakBytes)) deny("RESOURCE_ESTIMATE");
  return { freeBytes, sourceBytes, dependencyBytes, peakBytes, minimumFreeBytes: LIMITS.freeBytes, status: freeBytes >= Math.max(LIMITS.freeBytes, peakBytes) ? "ESTIMATE_ONLY" : "HOLD_HEADROOM", dependencyEstimate: "OWNER_REVIEW_REQUIRED", limits: LIMITS };
}
export function environmentPlan(scratch, runtimeDirectory, forbiddenRoots) {
  if (![scratch, runtimeDirectory, ...forbiddenRoots].every((v) => typeof v === "string" && isAbsolute(v))) deny("ENV_PATH");
  scratch = resolve(scratch); runtimeDirectory = resolve(runtimeDirectory);
  for (const root of forbiddenRoots) if (contained(resolve(root), scratch) || contained(scratch, resolve(root)) || contained(resolve(root), runtimeDirectory)) deny("ENV_ORIGINAL_FALLBACK");
  const at = (p) => join(scratch, p);
  // Pure declaration, not a child environment, directory creation or npm invocation.
  return { PATH: runtimeDirectory, HOME: at("home"), USERPROFILE: at("home"), APPDATA: at("home/appdata"), LOCALAPPDATA: at("home/local"), TMP: at("temp"), TEMP: at("temp"), TMPDIR: at("temp"), XDG_CACHE_HOME: at("cache"), XDG_CONFIG_HOME: at("config"), NPM_CONFIG_CACHE: at("npm/cache"), NPM_CONFIG_USERCONFIG: at("npm/user.npmrc"), NPM_CONFIG_GLOBALCONFIG: at("npm/global.npmrc"), NPM_CONFIG_PREFIX: at("npm/prefix"), PLAYWRIGHT_BROWSERS_PATH: at("playwright"), PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1", ROUTECAIRN_DASHBOARD_DIR: at("dashboard"), stdout: at("logs/stdout"), stderr: at("logs/stderr"), inheritedEnvironment: "NONE", network: "DENY_PENDING_SEPARATE_APPROVAL", lifecycle: "HOLD", runtimeCustody: "HOLD_NATIVE_REVIEW" };
}

// I/O boundary. BigInt identities avoid truncating native inode values.
export function identity(stat) {
  if (typeof stat.ino !== "bigint" || stat.ino === 0n || stat.dev === 0n) deny("UNCONTROLLED_IDENTITY");
  return Object.fromEntries(["dev", "ino", "nlink", "size", "mtimeNs", "ctimeNs"].map((key) => [key, String(stat[key])]));
}
const inode = (value) => value.dev + ":" + value.ino;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function contained(root, path) { const r = relative(root, path); return r === "" || (!isAbsolute(r) && r !== ".." && !r.startsWith(".." + sep)); }
function directory(path) {
  const stat = lstatSync(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== resolve(path)) deny("DIRECTORY_LINK_OR_ALIAS");
  return identity(stat);
}
export function captureRoot(root) {
  if (!isAbsolute(root)) deny("ROOT_ABSOLUTE"); root = resolve(root);
  const parents = []; let current = root;
  for (;;) { parents.push({ path: current, identity: directory(current) }); const next = dirname(current); if (next === current) break; current = next; }
  return { root, parents };
}
export function assertRoot(capture) {
  for (const item of capture.parents) {
    let actual;
    try { actual = directory(item.path); } catch (error) { if (error.code === "ENOENT") deny("PARENT_IDENTITY_CHANGED"); throw error; }
    if (inode(actual) !== inode(item.identity)) deny("PARENT_IDENTITY_CHANGED");
  }
}
function boundedNames(path, cap) {
  const before = directory(path), result = [], handle = opendirSync(path);
  try { for (;;) { const entry = handle.readSync(); if (!entry) break; if (result.length >= cap) deny("DIRECTORY_ENTRY_CAP"); portablePath(entry.name); result.push(entry.name); } }
  finally { handle.closeSync(); }
  if (inode(directory(path)) !== inode(before)) deny("PARENT_IDENTITY_CHANGED"); return result.sort();
}
export function readBounded(capture, name, expected, cap = LIMITS.inputBytes) {
  portablePath(name); assertRoot(capture);
  if (!Number.isSafeInteger(cap) || cap < 0 || cap > LIMITS.inputBytes) deny("READ_CAP");
  const path = resolve(capture.root, name); if (!contained(capture.root, path)) deny("CONTAINMENT");
  const parents = []; let parent = dirname(path);
  while (parent !== capture.root) { parents.push({ path: parent, identity: directory(parent) }); parent = dirname(parent); }
  const before = lstatSync(path, { bigint: true }), id = identity(before);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size > BigInt(cap) || realpathSync(path) !== path) deny("FILE_LINK_DEVICE_OR_CAP");
  if (expected && !same(id, expected)) deny("FILE_IDENTITY_CHANGED");
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    if (!same(identity(fstatSync(fd, { bigint: true })), id)) deny("FILE_IDENTITY_CHANGED");
    const bytes = Buffer.alloc(Number(before.size) + 1); let size = 0;
    while (size < bytes.length) { const count = readSync(fd, bytes, size, bytes.length - size, size); if (count === 0) break; size += count; }
    if (size !== Number(before.size) || !same(identity(fstatSync(fd, { bigint: true })), id) || !same(identity(lstatSync(path, { bigint: true })), id)) deny("FILE_CHANGED_DURING_READ");
    assertRoot(capture); for (const entry of parents) if (inode(directory(entry.path)) !== inode(entry.identity)) deny("PARENT_IDENTITY_CHANGED");
    const content = bytes.subarray(0, size); return { path: name, bytes: size, sha256: digest(content), identity: id, content };
  } finally { closeSync(fd); }
}
export function verifyEntries(capture, entries) {
  validateEntries(entries); const result = [];
  for (const entry of entries) { const file = readBounded(capture, entry.path, entry.currentIdentity); if (file.sha256 !== entry.sha256 || file.bytes !== entry.bytes) deny("SOURCE_HASH"); result.push({ path: file.path, bytes: file.bytes, sha256: file.sha256, currentIdentity: file.identity }); }
  return result;
}
export function inventoryTree(capture, prefix) {
  portablePath(prefix); const files = []; let visited = 0, total = 0;
  function walk(name, depth) {
    if (++visited > 4000 || depth > 18) deny("INVENTORY_CAP");
    const path = join(capture.root, portablePath(name)), stat = lstatSync(path, { bigint: true });
    if (stat.isSymbolicLink()) deny("INVENTORY_LINK");
    if (stat.isDirectory()) { directory(path); for (const child of boundedNames(path, 4000 - visited)) walk(name + "/" + child, depth + 1); }
    else { const file = readBounded(capture, name); total += file.bytes; if (total > LIMITS.sourceBytes) deny("BYTE_CAP"); files.push({ path: name, sha256: file.sha256, bytes: file.bytes, currentIdentity: file.identity }); }
  }
  assertRoot(capture); walk(prefix, 0); assertRoot(capture); return files;
}
export function freeBytesAt(capture) { assertRoot(capture); const stat = statfsSync(capture.root, { bigint: true }); const bytes = stat.bavail * stat.bsize; if (bytes > BigInt(Number.MAX_SAFE_INTEGER)) deny("RESOURCE_ESTIMATE"); return Number(bytes); }

// There is deliberately NO real-owner materialization entry point. The only
// writer accepts an opaque capability created here from 2–5 tiny caller-provided
// synthetic buffers; it cannot read any existing owner manifest or source tree.
const owned = new WeakMap();
function makeOwned(parent) {
  const parentCapture = captureRoot(parent); const root = mkdtempSync(join(parentCapture.root, "rc-a1-"));
  const capture = captureRoot(root); assertRoot(parentCapture);
  const marker = randomUUID(); exclusiveWrite(capture, "A1_OWNERSHIP", Buffer.from(marker));
  const token = Object.freeze({}); owned.set(token, { capture, parentCapture, marker, state: "OWNED", files: [] }); return token;
}
function owner(token) { const value = owned.get(token); if (!value || value.state !== "OWNED") deny("OWNERSHIP"); assertRoot(value.capture); assertRoot(value.parentCapture); if (readBounded(value.capture, "A1_OWNERSHIP", undefined, 64).content.toString() !== value.marker) deny("MARKER"); return value; }
function exclusiveWrite(capture, name, bytes) {
  portablePath(name); assertRoot(capture);
  const parts = name.split("/"); let parent = capture.root;
  for (const component of parts.slice(0, -1)) { const next = join(parent, component); try { mkdirSync(next); } catch (error) { if (error.code !== "EEXIST") throw error; } directory(next); parent = next; }
  const fd = openSync(join(capture.root, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
  try { let offset = 0; while (offset < bytes.length) { const n = writeSync(fd, bytes, offset, bytes.length - offset, offset); if (!n) deny("WRITE_SHORT"); offset += n; } const s = fstatSync(fd, { bigint: true }); if (s.nlink !== 1n || !s.isFile() || s.size !== BigInt(bytes.length)) deny("DESTINATION_IDENTITY"); }
  finally { closeSync(fd); }
  assertRoot(capture);
}
export function createSyntheticFixture(parent, entries) {
  if (!Array.isArray(entries) || entries.length < 2 || entries.length > 5) deny("SYNTHETIC_ONLY");
  exactNames(entries.map((v) => v.path), entries.map((v) => v.path));
  for (const entry of entries) if (entry.path === "A1_OWNERSHIP" || !Buffer.isBuffer(entry.content) || entry.content.length > 4096) deny("SYNTHETIC_ONLY");
  const token = makeOwned(parent), value = owner(token);
  for (const entry of entries) { exclusiveWrite(value.capture, entry.path, entry.content); const file = readBounded(value.capture, entry.path); value.files.push({ path: file.path, sha256: file.sha256, bytes: file.bytes, currentIdentity: file.identity }); }
  return token;
}
export function fixtureFacts(token) { const value = owner(token); return { root: value.capture.root, entries: structuredClone(value.files), parentIdentity: structuredClone(value.parentCapture.parents[0].identity), rootIdentity: structuredClone(value.capture.parents[0].identity), syntheticOnly: true }; }
export function verifySyntheticFixture(token) { const value = owner(token); return verifyEntries(value.capture, value.files); }
export function copySyntheticFixture(token, parent) {
  const value = owner(token); const original = verifySyntheticFixture(token);
  const entries = original.map((v) => ({ path: v.path, content: readBounded(value.capture, v.path, v.currentIdentity, 4096).content }));
  const copy = createSyntheticFixture(parent, entries), destination = owner(copy); verifySyntheticFixture(copy); verifySyntheticFixture(token);
  if (inode(destination.capture.parents[0].identity) === inode(value.capture.parents[0].identity)) deny("DESTINATION_ALIAS");
  for (let i = 0; i < original.length; i++) if (inode(original[i].currentIdentity) === inode(destination.files[i].currentIdentity)) deny("DESTINATION_ALIAS");
  return copy;
}
export function planCleanup(token) {
  const value = owner(token), capture = value.capture, entries = []; let bytes = 0;
  function walk(name, depth) {
    portablePath(name); if (depth > LIMITS.cleanupDepth || entries.length >= LIMITS.cleanupEntries) deny("CLEANUP_CAP");
    const path = join(capture.root, name), stat = lstatSync(path, { bigint: true }), id = identity(stat);
    if (stat.isSymbolicLink() || (!stat.isDirectory() && (!stat.isFile() || stat.nlink !== 1n))) deny("CLEANUP_LINK_DEVICE");
    if (stat.isDirectory()) { directory(path); entries.push({ path: name, directory: true, identity: id }); for (const child of boundedNames(path, LIMITS.cleanupEntries - entries.length)) walk(name + "/" + child, depth + 1); }
    else { bytes += Number(stat.size); if (bytes > LIMITS.cleanupBytes) deny("CLEANUP_BYTE_CAP"); entries.push({ path: name, directory: false, identity: id }); }
  }
  for (const name of boundedNames(capture.root, LIMITS.cleanupEntries)) walk(name, 1);
  owner(token); return { entries, bytes, rootIdentity: capture.parents[0].identity, completeBeforeDeletion: true };
}
export function cleanupSyntheticFixture(token, beforeOperation = () => {}) {
  const value = owner(token), plan = planCleanup(token); let removed = 0;
  const directories = new Map(plan.entries.filter((v) => v.directory).map((v) => [v.path, v]));
  const ordered = plan.entries.filter((v) => v.path !== "A1_OWNERSHIP").sort((a, b) => b.path.split("/").length - a.path.split("/").length || a.path.localeCompare(b.path));
  ordered.push(plan.entries.find((v) => v.path === "A1_OWNERSHIP"));
  try {
    for (const entry of ordered) {
      beforeOperation(removed, entry.path); owner(token);
      let parent = dirname(join(value.capture.root, entry.path));
      while (parent !== value.capture.root) { const name = relative(value.capture.root, parent).split(sep).join("/"); const recorded = directories.get(name); if (!recorded || inode(directory(parent)) !== inode(recorded.identity)) deny("CLEANUP_PARENT_CHANGED"); parent = dirname(parent); }
      const target = join(value.capture.root, entry.path), now = lstatSync(target, { bigint: true });
      if (now.isSymbolicLink() || (entry.directory ? inode(identity(now)) !== inode(entry.identity) || !now.isDirectory() : !same(identity(now), entry.identity) || !now.isFile() || now.nlink !== 1n)) deny("CLEANUP_IDENTITY_CHANGED");
      if (entry.path === "A1_OWNERSHIP" && boundedNames(value.capture.root, LIMITS.cleanupEntries).join("\n") !== "A1_OWNERSHIP") deny("CLEANUP_EXTRA_ENTRY");
      if (entry.directory) rmdirSync(target); else unlinkSync(target); removed++;
    }
    assertRoot(value.capture); assertRoot(value.parentCapture); rmdirSync(value.capture.root); value.state = "DISPOSED";
    return { status: "CONFIRMED", removed, recursiveDelete: false, sentinel: "CALLER_MUST_VERIFY" };
  } catch (error) {
    value.state = "RETAINED";
    // A partial delete never becomes a successful cleanup or replayable token.
    return { status: "RETAINED_INCOMPLETE", removed, reason: /^A1_[A-Z_]+$/.test(error.message) ? error.message : "A1_NATIVE_DELETE_FAILED", rootRetained: true, recursiveDelete: false };
  }
}

// A1B PROPOSED AMENDMENT, SYNTHETIC OPT-IN ONLY. This is additional aggregate
// deletion authority, not an increase or replacement of legacy LIMITS above.
// Measured source: 609 files +124 dirs +marker +root =735. The larger fixed
// proof: 750 files +the same124 dirs +marker +root =876. No deps/build/consumer.
export const STRUCTURAL_CLEANUP_PROPOSAL = Object.freeze({ id: "A1B_SYNTHETIC_PROPOSAL_V1", status: "PROPOSED_REVIEW_REQUIRED", realUseAuthorized: false, perBatch: 512, entries: 876, files: 750, directories: 124, bytes: 14_649_759, singleFileBytes: 3_849_998, depth: 5, fanout: 125, operationMs: 25_000 });
const structuralOwners = new WeakMap();
const structuralMarker = "A1B_OWNERSHIP";
const profiles = Object.freeze({ entries511: 385, entries512: 386, entries513: 387, files609: 609, files750: 750 });
const tick = () => Number(process.hrtime.bigint() / 1_000_000n);
const structuralDeny = (code) => { throw Error("A1B_" + code); };
function structuralValue(token, states) { const v = structuralOwners.get(token); if (!v || !states.includes(v.state)) structuralDeny("CAPABILITY_STATE"); return v; }
function withinDeadline(deadline) { if (tick() > deadline) structuralDeny("DEADLINE"); }
function freezePlan(object) { if (object && typeof object === "object") { for (const value of Object.values(object)) freezePlan(value); Object.freeze(object); } return object; }
function structuralIdentity(path, kind, dev) {
  const stat = lstatSync(path, { bigint: true });
  if (stat.isSymbolicLink() || (kind === "directory" ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1n) || String(stat.dev) !== dev || realpathSync.native(path) !== resolve(path)) structuralDeny("TYPE_LINK_MOUNT_OR_ALIAS");
  return identity(stat);
}
function structuralBoundedNames(v, path) {
  const target = path === null ? v.capture.root : join(v.capture.root, path), before = structuralIdentity(target, "directory", v.rootIdentity.dev), names = [], handle = opendirSync(target);
  try { for (;;) { const entry = handle.readSync(); if (!entry) break; if (names.length >= STRUCTURAL_CLEANUP_PROPOSAL.fanout) structuralDeny("FANOUT_CAP"); portablePath(entry.name); names.push(entry.name); } }
  finally { handle.closeSync(); }
  if (!same(structuralIdentity(target, "directory", v.rootIdentity.dev), before)) structuralDeny("DIRECTORY_CHANGED_DURING_SCAN");
  return names.sort();
}
function structuralRootGuard(v) {
  for (const entry of v.capture.parents.slice(1)) {
    const stat = lstatSync(entry.path, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink() || inode(identity(stat)) !== inode(entry.identity) || String(stat.nlink) !== entry.identity.nlink) structuralDeny("OUTER_PARENT_CHANGED");
  }
  const current = structuralIdentity(v.capture.root, "directory", v.rootIdentity.dev);
  if (!same(current, v.liveDirectories.get(null))) structuralDeny("ROOT_IDENTITY_CHANGED");
}
function structuralRead(v, member) {
  const path = join(v.capture.root, member.path), before = structuralIdentity(path, "file", v.rootIdentity.dev);
  if (!same(before, member.identity) || Number(before.size) !== member.bytes || member.bytes > STRUCTURAL_CLEANUP_PROPOSAL.singleFileBytes) structuralDeny("FILE_IDENTITY_CHANGED");
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    if (!same(identity(fstatSync(fd, { bigint: true })), before)) structuralDeny("DESCRIPTOR_CHANGED");
    const bytes = Buffer.alloc(member.bytes + 1); let offset = 0;
    while (offset < bytes.length) { const n = readSync(fd, bytes, offset, bytes.length - offset, offset); if (!n) break; offset += n; }
    if (offset !== member.bytes || !same(identity(fstatSync(fd, { bigint: true })), before) || !same(identity(lstatSync(path, { bigint: true })), before) || digest(bytes.subarray(0, offset)) !== member.sha256) structuralDeny("FILE_BYTES_CHANGED");
  } finally { closeSync(fd); }
}
function structuralMarkerGuard(v) {
  if (v.markerRemoved) structuralDeny("MARKER_ALREADY_REMOVED");
  structuralRead(v, v.expected.get(structuralMarker));
}
function structuralChildren(v, parentPath) {
  return (v.children.get(parentPath) || []).filter((p) => !v.removed.has(p)).sort();
}
function structuralNames(v, parentPath) {
  const actual = structuralBoundedNames(v, parentPath);
  const expected = structuralChildren(v, parentPath).map((p) => p.slice((parentPath?.length || -1) + 1)).sort();
  exactNames(actual, expected);
}
function structuralParents(v, member) {
  structuralRootGuard(v);
  let parent = member.parent;
  while (parent !== null) {
    const expected = v.liveDirectories.get(parent), id = structuralIdentity(join(v.capture.root, parent), "directory", v.rootIdentity.dev);
    if (!expected || !same(id, expected)) structuralDeny("PARENT_IDENTITY_CHANGED");
    parent = v.expected.get(parent).parent;
  }
}
function structuralSnapshot(v, deadline, provenance = true) {
  const p = STRUCTURAL_CLEANUP_PROPOSAL, result = [], seen = new Set(); let totalBytes = 0, files = 0, dirs = 0;
  function visit(path, depth) {
    withinDeadline(deadline);
    if (depth > p.depth || result.length >= p.entries) structuralDeny("GLOBAL_COUNT_OR_DEPTH");
    if (path !== null) { portablePath(path); if (seen.has(path.toLowerCase())) structuralDeny("CASE_COLLISION"); seen.add(path.toLowerCase()); }
    const target = path === null ? v.capture.root : join(v.capture.root, path), stat = lstatSync(target, { bigint: true });
    if (stat.isSymbolicLink() || (!stat.isDirectory() && (!stat.isFile() || stat.nlink !== 1n)) || String(stat.dev) !== v.rootIdentity.dev || realpathSync.native(target) !== target) structuralDeny("TYPE_LINK_MOUNT_OR_ALIAS");
    const kind = path === null ? "root" : stat.isDirectory() ? "directory" : path === structuralMarker ? "marker" : "file";
    const bytes = stat.isFile() ? Number(stat.size) : 0;
    if (bytes > p.singleFileBytes) structuralDeny("SINGLE_FILE_CAP");
    totalBytes += bytes; if (totalBytes > p.bytes) structuralDeny("GLOBAL_BYTE_CAP");
    if (kind === "file" && ++files > p.files) structuralDeny("GLOBAL_FILE_CAP");
    if (kind === "directory" && ++dirs > p.directories) structuralDeny("GLOBAL_DIRECTORY_CAP");
    result.push({ path, kind, bytes, identity: identity(stat) });
    if (stat.isDirectory()) for (const name of structuralBoundedNames(v, path)) visit(path === null ? name : path + "/" + name, depth + 1);
  }
  structuralRootGuard(v); visit(null, 0);
  const expectedPaths = [...v.expected.keys()].filter((path) => !v.removed.has(path));
  exactNames(result.filter((e) => e.path !== null).map((e) => e.path), expectedPaths.filter((path) => path !== null));
  if (result.length !== expectedPaths.length) structuralDeny("COVERAGE");
  for (const entry of result) {
    const expected = v.expected.get(entry.path), id = entry.kind === "root" || entry.kind === "directory" ? v.liveDirectories.get(entry.path) : expected.identity;
    if (entry.kind !== expected.kind || !same(entry.identity, id) || entry.bytes !== expected.bytes) structuralDeny("MEMBER_IDENTITY_CHANGED");
    if (provenance && (entry.kind === "file" || entry.kind === "marker")) structuralRead(v, expected);
  }
  structuralRootGuard(v); if (!v.markerRemoved) structuralMarkerGuard(v);
  return { result, totalBytes, files, directories: dirs };
}

// Pure schedule validation never gives deletion authority or accepts a root path.
export function validateStructuralSchedule(plan) {
  const p = STRUCTURAL_CLEANUP_PROPOSAL;
  if (!plan || plan.policyId !== p.id || !Array.isArray(plan.entries) || plan.entries.length < 2 || plan.entries.length > p.entries || !Array.isArray(plan.batches)) structuralDeny("SCHEDULE");
  const entries = plan.entries, paths = [], positions = new Map(), flat = [], fanout = new Map(); let bytes = 0, files = 0, dirs = 0;
  if (!/^[a-f0-9]{64}$/.test(plan.generationSha256)) structuralDeny("SCHEDULE_GENERATION");
  if (entries[0].kind !== "root" || entries[0].path !== null || entries.filter((v) => v.kind === "root").length !== 1 || entries.filter((v) => v.kind === "marker").length !== 1) structuralDeny("SCHEDULE_ROOT_MARKER");
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]; if (e.id !== i || !["root", "marker", "file", "directory"].includes(e.kind)) structuralDeny("SCHEDULE_MEMBER");
    if (!e.identity || ["dev", "ino", "nlink", "size", "mtimeNs", "ctimeNs"].some((k) => typeof e.identity[k] !== "string" || !/^[0-9]{1,32}$/.test(e.identity[k])) || e.identity.dev === "0" || e.identity.ino === "0") structuralDeny("SCHEDULE_IDENTITY");
    if (e.kind === "file" || e.kind === "marker") { if (e.identity.nlink !== "1" || e.identity.size !== String(e.bytes) || !/^[a-f0-9]{64}$/.test(e.sha256)) structuralDeny("SCHEDULE_FILE"); }
    else if (e.bytes !== 0) structuralDeny("SCHEDULE_DIRECTORY_BYTES");
    if (e.kind === "file" && ++files > p.files) structuralDeny("SCHEDULE_FILE_CAP");
    if (e.kind === "directory" && ++dirs > p.directories) structuralDeny("SCHEDULE_DIRECTORY_CAP");
    if (e.path !== null) { portablePath(e.path); paths.push(e.path); if (e.path.split("/").length > p.depth) structuralDeny("SCHEDULE_DEPTH"); }
    if (!Number.isSafeInteger(e.bytes) || e.bytes < 0 || e.bytes > p.singleFileBytes) structuralDeny("SCHEDULE_BYTES"); bytes += e.bytes;
    if (e.kind !== "root") { const parent = entries[e.parentId]; const expectedParent = e.path.includes("/") ? e.path.slice(0, e.path.lastIndexOf("/")) : null; if (!parent || !["root", "directory"].includes(parent.kind) || parent.path !== expectedParent) structuralDeny("SCHEDULE_PARENT"); fanout.set(e.parentId, (fanout.get(e.parentId) || 0) + 1); if (fanout.get(e.parentId) > p.fanout) structuralDeny("SCHEDULE_FANOUT"); }
    else if (e.parentId !== null) structuralDeny("SCHEDULE_PARENT");
  }
  exactNames(paths, paths); if (bytes > p.bytes) structuralDeny("SCHEDULE_BYTES");
  for (const batch of plan.batches) { if (!Array.isArray(batch) || batch.length < 1 || batch.length > p.perBatch) structuralDeny("BATCH_CAP"); for (const id of batch) { if (!Number.isInteger(id) || !entries[id] || positions.has(id)) structuralDeny("SCHEDULE_DUPLICATE"); positions.set(id, flat.length); flat.push(id); } }
  if (flat.length !== entries.length) structuralDeny("SCHEDULE_MISSING");
  const marker = entries.find((e) => e.kind === "marker");
  if (marker.path !== structuralMarker || marker.bytes !== 36 || marker.sha256 !== plan.generationSha256 || flat.at(-1) !== 0 || flat.at(-2) !== marker.id || !plan.batches.at(-1).includes(marker.id)) structuralDeny("SCHEDULE_TERMINAL_ORDER");
  for (const e of entries.slice(1)) if (positions.get(e.id) >= positions.get(e.parentId)) structuralDeny("SCHEDULE_POSTORDER");
  return { status: "VALIDATED_PURE_ONLY", entries: entries.length, batches: plan.batches.map((v) => v.length), perBatchLimit: p.perBatch, deletionAuthority: false };
}

export function createStructuralSyntheticFixture(parent, profile, policyId) {
  const p = STRUCTURAL_CLEANUP_PROPOSAL;
  if (policyId !== p.id || typeof profile !== "string" || !Object.hasOwn(profiles, profile)) structuralDeny("SYNTHETIC_OPT_IN_ONLY");
  if (typeof parent !== "string" || !isAbsolute(parent) || /^[\\/]{2}/.test(parent) || parent.includes("\0")) structuralDeny("PARENT_SYNTAX");
  if (typeof realpathSync.native !== "function") structuralDeny("NATIVE_CANONICAL_UNAVAILABLE");
  const deadline = tick() + p.operationMs, parentCapture = captureRoot(parent);
  if (freeBytesAt(parentCapture) < LIMITS.freeBytes) structuralDeny("HEADROOM");
  const root = mkdtempSync(join(parentCapture.root, "rc-a1b-")), capture = captureRoot(root), generation = randomUUID();
  // Only generated constants; no caller file bytes, source manifest or adopt-root.
  exclusiveWrite(capture, structuralMarker, Buffer.from(generation));
  const expected = new Map(), children = new Map([[null, [structuralMarker]]]), directoryOrigins = new Map(), markerOrigin = identity(lstatSync(join(root, structuralMarker), { bigint: true }));
  for (let i = 0; i < p.directories; i++) { const name = "d" + String(i).padStart(3, "0"); mkdirSync(join(root, name)); directoryOrigins.set(name, identity(lstatSync(join(root, name), { bigint: true }))); children.get(null).push(name); children.set(name, []); }
  for (let i = 0; i < profiles[profile]; i++) {
    withinDeadline(deadline); const dir = "d" + String(i % p.directories).padStart(3, "0"), name = dir + "/f" + String(i).padStart(4, "0") + ".txt", content = Buffer.from("A1B generated " + i + "\n");
    const id = structuralGeneratedWrite(capture, name, content, directoryOrigins.get(dir)); expected.set(name, { path: name, kind: "file", bytes: content.length, sha256: digest(content), identity: id, parent: dir }); children.get(dir).push(name);
  }
  for (const dir of [...children.keys()].filter((v) => v !== null)) { const id = structuralIdentity(join(root, dir), "directory", capture.parents[0].identity.dev); if (inode(id) !== inode(directoryOrigins.get(dir)) || id.nlink !== directoryOrigins.get(dir).nlink) structuralDeny("GENERATOR_PARENT_CHANGED"); expected.set(dir, { path: dir, kind: "directory", bytes: 0, identity: id, parent: null }); }
  expected.set(structuralMarker, { path: structuralMarker, kind: "marker", bytes: 36, sha256: digest(generation), identity: markerOrigin, parent: null });
  const finalCapture = captureRoot(root), rootIdentity = finalCapture.parents[0].identity; expected.set(null, { path: null, kind: "root", bytes: 0, identity: rootIdentity, parent: null });
  const token = Object.freeze({}), liveDirectories = new Map([...expected].filter(([, e]) => ["root", "directory"].includes(e.kind)).map(([path, e]) => [path, e.identity]));
  structuralOwners.set(token, { capture: finalCapture, rootIdentity, expected, children, liveDirectories, generationSha256: digest(generation), profile, state: "OWNED", removed: new Set(), markerRemoved: false }); return token;
}
// Fixed-generator writer only. Native canonical resolution avoids repeatedly
// emulating path resolution component-by-component; all ancestor IDs/types and
// descriptor/path identities are still checked before and after each write.
function structuralGeneratedWrite(capture, name, bytes, parentOrigin) {
  portablePath(name); if (bytes.length > 64) structuralDeny("GENERATED_BYTES");
  function guard() {
    for (const entry of capture.parents) { const s = lstatSync(entry.path, { bigint: true }); if (!s.isDirectory() || s.isSymbolicLink() || inode(identity(s)) !== inode(entry.identity) || (entry.path !== capture.root && String(s.nlink) !== entry.identity.nlink)) structuralDeny("GENERATOR_PARENT_CHANGED"); }
    if (realpathSync.native(capture.root) !== capture.root) structuralDeny("GENERATOR_ROOT_ALIAS");
  }
  guard(); const parent = dirname(join(capture.root, name)), dev = capture.parents[0].identity.dev, parentId = structuralIdentity(parent, "directory", dev);
  if (inode(parentId) !== inode(parentOrigin) || parentId.nlink !== parentOrigin.nlink) structuralDeny("GENERATOR_PARENT_CHANGED");
  const target = join(capture.root, name), fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
  let descriptorIdentity;
  try {
    let offset = 0; while (offset < bytes.length) { const n = writeSync(fd, bytes, offset, bytes.length - offset, offset); if (!n) structuralDeny("GENERATOR_WRITE_SHORT"); offset += n; }
    const s = fstatSync(fd, { bigint: true }); descriptorIdentity = identity(s); if (!s.isFile() || s.nlink !== 1n || String(s.dev) !== dev || s.size !== BigInt(bytes.length) || !same(descriptorIdentity, identity(lstatSync(target, { bigint: true })))) structuralDeny("GENERATOR_FILE_CHANGED");
  } finally { closeSync(fd); }
  guard(); const after = structuralIdentity(parent, "directory", dev); if (inode(after) !== inode(parentId) || after.nlink !== parentId.nlink) structuralDeny("GENERATOR_PARENT_CHANGED");
  const finalId = structuralIdentity(target, "file", dev); if (inode(finalId) !== inode(descriptorIdentity) || finalId.nlink !== descriptorIdentity.nlink || finalId.size !== descriptorIdentity.size) structuralDeny("GENERATOR_FILE_CHANGED"); return finalId;
}
export function structuralFixtureFacts(token) {
  const v = structuralValue(token, ["OWNED", "PLANNED"]);
  return { root: v.capture.root, profile: v.profile, files: profiles[v.profile], expectedEntries: v.expected.size, syntheticOnly: true };
}
export function planStructuralCleanup(token) {
  const v = structuralValue(token, ["OWNED"]), deadline = tick() + STRUCTURAL_CLEANUP_PROPOSAL.operationMs;
  try {
    const snapshot = structuralSnapshot(v, deadline), orderedPaths = [null, ...[...v.expected.keys()].filter((p) => p !== null).sort()], ids = new Map(orderedPaths.map((p, i) => [p, i]));
    const entries = orderedPaths.map((path, id) => ({ ...v.expected.get(path), id, parentId: path === null ? null : ids.get(v.expected.get(path).parent) }));
    const deletion = entries.filter((e) => !["root", "marker"].includes(e.kind)).sort((a, b) => b.path.split("/").length - a.path.split("/").length || (a.path < b.path ? -1 : 1)).map((e) => e.id);
    deletion.push(entries.find((e) => e.kind === "marker").id, 0); const batches = [];
    for (let i = 0; i < deletion.length;) { const left = deletion.length - i, n = left === 513 ? 511 : Math.min(512, left); batches.push(deletion.slice(i, i + n)); i += n; }
    const plan = { schemaVersion: 1, policyId: STRUCTURAL_CLEANUP_PROPOSAL.id, generationSha256: v.generationSha256, provenance: "FIXED_GENERATED_SYNTHETIC_V1", entries, batches, bytes: snapshot.totalBytes, files: snapshot.files, directories: snapshot.directories, completeBeforeDeletion: true, realUseAuthorized: false };
    validateStructuralSchedule(plan); v.plan = freezePlan(plan); v.state = "PLANNED"; return structuredClone(plan);
  } catch (error) { v.state = "RETAINED"; throw error; }
}
export function cleanupStructuralFixture(token, hooks = {}) {
  const v = structuralValue(token, ["OWNED", "PLANNED"]), deadline = tick() + STRUCTURAL_CLEANUP_PROPOSAL.operationMs;
  let removed = 0, batchesCompleted = 0, phase = "GLOBAL_PREFLIGHT", batchIndex = -1;
  try {
    if (v.state === "OWNED") planStructuralCleanup(token);
    validateStructuralSchedule(v.plan); v.state = "DELETING";
    if (!hooks || Object.keys(hooks).some((k) => !["beforeBatch", "beforeDelete"].includes(k)) || Object.values(hooks).some((f) => typeof f !== "function")) structuralDeny("HOOKS");
    for (batchIndex = 0; batchIndex < v.plan.batches.length; batchIndex++) {
      phase = "BATCH_PREFLIGHT"; withinDeadline(deadline);
      if (hooks.beforeBatch && hooks.beforeBatch(Object.freeze({ batchIndex, removed })) !== undefined) structuralDeny("ASYNC_OR_INVALID_HOOK");
      structuralSnapshot(v, deadline);
      const batch = v.plan.batches[batchIndex]; if (batch.length > 512) structuralDeny("BATCH_CAP");
      for (const id of batch) {
        withinDeadline(deadline); const member = v.plan.entries[id]; phase = member.kind === "root" ? "ROOT_REMOVAL" : member.kind === "marker" ? "MARKER_REMOVAL" : "MEMBER_REMOVAL";
        if (hooks.beforeDelete && hooks.beforeDelete(Object.freeze({ batchIndex, removed, member: freezePlan(structuredClone(member)) })) !== undefined) structuralDeny("ASYNC_OR_INVALID_HOOK");
        if (v.removed.has(member.path) || !batch.includes(id) || v.plan.generationSha256 !== v.generationSha256) structuralDeny("MEMBERSHIP_OR_GENERATION");
        structuralParents(v, member);
        if (member.kind === "root") {
          if (!v.markerRemoved || v.removed.size !== v.expected.size - 1) structuralDeny("ROOT_ORDER"); structuralNames(v, null); rmdirSync(v.capture.root);
        } else {
          structuralMarkerGuard(v);
          const expectedIdentity = member.kind === "directory" ? v.liveDirectories.get(member.path) : member.identity, now = structuralIdentity(join(v.capture.root, member.path), member.kind === "directory" ? "directory" : "file", v.rootIdentity.dev);
          if (!same(now, expectedIdentity)) structuralDeny("TARGET_IDENTITY_CHANGED");
          if (member.kind === "directory") { structuralNames(v, member.path); rmdirSync(join(v.capture.root, member.path)); }
          else { structuralRead(v, member); unlinkSync(join(v.capture.root, member.path)); }
        }
        removed++; v.removed.add(member.path); if (member.kind === "marker") v.markerRemoved = true;
        if (member.kind !== "root") {
          // Only confirmed planned deletion may advance a parent's expected
          // timestamps/size/nlink. No scan grants authority for new children.
          const parent = member.parent, target = parent === null ? v.capture.root : join(v.capture.root, parent), next = structuralIdentity(target, "directory", v.rootIdentity.dev), previous = v.liveDirectories.get(parent);
          const decrement = member.kind === "directory" && process.platform !== "win32" ? 1n : 0n;
          if (inode(next) !== inode(previous) || BigInt(next.nlink) !== BigInt(previous.nlink) - decrement) structuralDeny("PARENT_LINK_PROFILE");
          structuralNames(v, parent); v.liveDirectories.set(parent, next);
        }
      }
      batchesCompleted++;
    }
    v.state = "DISPOSED";
    return { status: "CONFIRMED", phase: "COMPLETE", removed, planned: v.plan.entries.length, batchesCompleted, batchSizes: v.plan.batches.map((b) => b.length), marker: "REMOVED_LAST_BEFORE_ROOT", root: "REMOVED_LAST", recursiveDelete: false, realUseAuthorized: false };
  } catch (error) {
    v.state = "RETAINED";
    return { status: "RETAINED_INCOMPLETE", phase, removed, planned: v.plan?.entries.length || v.expected.size, batchesCompleted, batchIndex, marker: v.markerRemoved ? "REMOVED" : "NOT_CONFIRMED_REMOVED", root: "NOT_CONFIRMED_REMOVED", reason: /^A1B?_[A-Z_]+$/.test(error.message) ? error.message : "A1B_NATIVE_OR_INJECTED_FAILURE", nativeCode: typeof error.code === "string" && /^[A-Z]+$/.test(error.code) ? error.code : undefined, automaticRetry: false, recursiveDelete: false, realUseAuthorized: false };
  }
}

const nestedDirectoryNames = Object.freeze([
  "apps",
  "apps/dashboard-ui",
  "apps/dashboard-ui/src",
  "benchmarks",
  "deploy",
  "deploy/control-plane",
  "deploy/helm",
  "deploy/helm/routecairn",
  "deploy/helm/routecairn/templates",
  "deploy/module-registry",
  "deploy/oast",
  "docs",
  "examples",
  "examples/modules",
  "examples/modules/framework-fingerprint",
  "examples/modules/graphql-response",
  "examples/modules/security-headers",
  "scripts",
  "src",
  "src/benchmark",
  "src/benchmark/fixtures",
  "src/cli",
  "src/cli/agent",
  "src/cli/commands",
  "src/config",
  "src/controlPlane",
  "src/core",
  "src/core/auth",
  "src/core/authorization",
  "src/core/comparisons",
  "src/core/engine",
  "src/core/errors",
  "src/core/evidence",
  "src/core/files",
  "src/core/findings",
  "src/core/http",
  "src/core/logging",
  "src/core/net",
  "src/core/offensive",
  "src/core/planning",
  "src/core/plugins",
  "src/core/scope",
  "src/core/urls",
  "src/dashboard",
  "src/dashboard/admin",
  "src/dashboard/auth",
  "src/dashboard/comparisons",
  "src/dashboard/contracts",
  "src/dashboard/credentials",
  "src/dashboard/db",
  "src/dashboard/demo",
  "src/dashboard/execution",
  "src/dashboard/findings",
  "src/dashboard/import",
  "src/dashboard/operations",
  "src/dashboard/proofPacks",
  "src/dashboard/retests",
  "src/dashboard/reviews",
  "src/dashboard/security",
  "src/dashboard/server",
  "src/dashboard/services",
  "src/dashboard/types",
  "src/dashboard/worker",
  "src/intelligence",
  "src/intelligence/apiSafety",
  "src/intelligence/evidenceTemplates",
  "src/intelligence/inventory",
  "src/intelligence/manualTesting",
  "src/intelligence/parameters",
  "src/intelligence/recommendations",
  "src/modules",
  "src/modules/activeVulnerability",
  "src/modules/apiGraphql",
  "src/modules/apiMapper",
  "src/modules/apiProbe",
  "src/modules/assistedReview",
  "src/modules/authSurface",
  "src/modules/authenticatedTesting",
  "src/modules/authenticationLifecycle",
  "src/modules/authorizationMatrix",
  "src/modules/baseline",
  "src/modules/billingEntitlement",
  "src/modules/browserCrawler",
  "src/modules/bulkAuthorization",
  "src/modules/businessInvariant",
  "src/modules/changeMonitor",
  "src/modules/collectionAuthorization",
  "src/modules/controlledRace",
  "src/modules/cookieReview",
  "src/modules/corsReview",
  "src/modules/equivalentRouteTesting",
  "src/modules/exposureReview",
  "src/modules/fieldExposureTesting",
  "src/modules/fileAuthorization",
  "src/modules/headerReview",
  "src/modules/jsIntelligence",
  "src/modules/linkPortalSecurity",
  "src/modules/methodReview",
  "src/modules/nextjsReview",
  "src/modules/objectPairTesting",
  "src/modules/operationalEndpointSecurity",
  "src/modules/parameterAnalysis",
  "src/modules/pathDiscovery",
  "src/modules/preHandover",
  "src/modules/privilegeMutation",
  "src/modules/proofMode",
  "src/modules/protocolSecurity",
  "src/modules/responseAnalysis",
  "src/modules/roleComparison",
  "src/modules/secretBoundary",
  "src/modules/stateAwareApi",
  "src/modules/supabaseAuthorization",
  "src/modules/techFingerprint",
  "src/modules/vulnerabilityWorkflows",
  "src/modules/workflowValidation",
  "src/oast",
  "src/reports",
  "src/standards",
  "src/standards/catalog",
  "src/storage",
  "src/triage",
  "src/validation",
  "standards",
  "standards/sources"
]);

// Nested topology follow-on: fixed test labels only. The preceding A1/A1B
// module, cleanup semantics, policy limits and existing profiles are unchanged.
export function createNestedStructuralSyntheticFixture(parent, profile, policyId) {
  const p = STRUCTURAL_CLEANUP_PROPOSAL;
  if (policyId !== p.id || !["files609", "files750"].includes(profile)) structuralDeny("NESTED_SYNTHETIC_OPT_IN_ONLY");
  if (digest(JSON.stringify(nestedDirectoryNames)) !== "c78542985009c6e2d47744c4aa47150a96b34914d8dc80772039d949011e1d64") structuralDeny("NESTED_TEMPLATE_PIN");
  if (typeof parent !== "string" || !isAbsolute(parent) || /^[\\/]{2}/.test(parent) || parent.includes("\0")) structuralDeny("PARENT_SYNTAX");
  if (typeof realpathSync.native !== "function") structuralDeny("NATIVE_CANONICAL_UNAVAILABLE");
  const deadline = tick() + p.operationMs, parentCapture = captureRoot(parent);
  if (freeBytesAt(parentCapture) < LIMITS.freeBytes) structuralDeny("HEADROOM");
  const root = mkdtempSync(join(parentCapture.root, "rc-a1b-nested-")), initial = captureRoot(root), generation = randomUUID();
  exclusiveWrite(initial, structuralMarker, Buffer.from(generation));
  const capture = captureRoot(root), rootIdentity = capture.parents[0].identity;
  const expected = new Map([[null, { path: null, kind: "root", bytes: 0, identity: rootIdentity, parent: null }], [structuralMarker, { path: structuralMarker, kind: "marker", bytes: 36, sha256: digest(generation), identity: structuralIdentity(join(root, structuralMarker), "file", rootIdentity.dev), parent: null }]]);
  const v = { capture, rootIdentity, expected, children: new Map([[null, [structuralMarker]]]), liveDirectories: new Map([[null, rootIdentity]]), generationSha256: digest(generation), profile, state: "OWNED", removed: new Set(), markerRemoved: false };
  // Only a confirmed exclusive creation may advance its direct parent's
  // expected metadata; coverage still uses the fixed generated membership.
  function advanceParent(path, directoryCreated) {
    const target = path === null ? root : join(root, path), next = structuralIdentity(target, "directory", rootIdentity.dev), previous = v.liveDirectories.get(path);
    const increment = directoryCreated && process.platform !== "win32" ? 1n : 0n;
    if (inode(next) !== inode(previous) || BigInt(next.nlink) !== BigInt(previous.nlink) + increment) structuralDeny("NESTED_GENERATOR_PARENT_CHANGED");
    structuralNames(v, path); v.liveDirectories.set(path, next); structuralParents(v, { parent: path });
  }
  const creation = [...nestedDirectoryNames].sort((a, b) => a.split("/").length - b.split("/").length || (a < b ? -1 : 1));
  for (const path of creation) {
    withinDeadline(deadline); portablePath(path);
    const parentPath = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : null;
    structuralParents(v, { parent: parentPath });
    mkdirSync(join(root, path));
    const id = structuralIdentity(join(root, path), "directory", rootIdentity.dev);
    expected.set(path, { path, kind: "directory", bytes: 0, identity: id, parent: parentPath });
    v.children.set(path, []); v.children.get(parentPath).push(path); v.liveDirectories.set(path, id);
    advanceParent(parentPath, true);
  }
  for (let i = 0; i < profiles[profile]; i++) {
    withinDeadline(deadline);
    const dir = nestedDirectoryNames[i % nestedDirectoryNames.length], name = dir + "/f" + String(i).padStart(4, "0") + ".txt", bytes = Buffer.from("A1B generated " + i + "\n");
    structuralParents(v, { parent: dir });
    const id = structuralGeneratedWrite(capture, name, bytes, v.liveDirectories.get(dir));
    expected.set(name, { path: name, kind: "file", bytes: bytes.length, sha256: digest(bytes), identity: id, parent: dir }); v.children.get(dir).push(name);
    advanceParent(dir, false);
  }
  structuralRootGuard(v);
  for (const [path, id] of v.liveDirectories) expected.set(path, { ...expected.get(path), identity: id });
  const finalCapture = captureRoot(root);
  if (!same(finalCapture.parents[0].identity, v.liveDirectories.get(null))) structuralDeny("NESTED_GENERATOR_ROOT_CHANGED");
  v.capture = finalCapture; v.rootIdentity = finalCapture.parents[0].identity;
  structuralSnapshot(v, deadline);
  const token = Object.freeze({}); structuralOwners.set(token, v); return token;
}
