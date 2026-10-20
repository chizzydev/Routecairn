import { afterAll, describe, expect, it } from "vitest";
import { appendFileSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmdirSync, symlinkSync, truncateSync, unlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { PIN, LIMITS, A1_PATHS, digest, portablePath, exactNames, validateEntries, manifestDigest, assertGitState, dependencyClosure, packagePath, auditCandidate, resourcePlan, environmentPlan, captureRoot, readBounded, verifyEntries, createSyntheticFixture, fixtureFacts, verifySyntheticFixture, copySyntheticFixture, planCleanup, cleanupSyntheticFixture } from "../../scripts/safe-release-isolation.mjs";
import { parseArguments, parseStatus, analyzeBuildClosure } from "../../scripts/safe-release-preflight.mjs";
import ts from "typescript";

// This suite needs a caller-created disposable lab, never user temp by default.
const approvedParent = process.env.ROUTECAIRN_A1_LAB;
if (!approvedParent || !existsSync(approvedParent)) throw Error("A1_TEST_OWNED_LAB_REQUIRED");
const parent = mkdtempSync(join(resolve(approvedParent), "a1-suite-"));
const sentinel = join(parent, "ORIGINAL_SYNTHETIC_SENTINEL");
writeFileSync(sentinel, "A1_SYNTHETIC_SENTINEL", { flag: "wx" });
const sentinelHash = digest(readFileSync(sentinel)), cases: object[] = [];
let sequence = 0;
const record = (id: string, status: string, facts: object = {}) => cases.push({ id, status, ...facts });
const tiny = () => [{ path: "src/a.ts", content: Buffer.from("export const a = 1;\n") }, { path: "assets/b.json", content: Buffer.from("{}\n") }];
const entry = (path: string, content = "safe") => ({ path, content: Buffer.from(content), bytes: Buffer.byteLength(content), sha256: digest(content) });
const fresh = () => createSyntheticFixture(parent, tiny());
const safe = () => expect(digest(readFileSync(sentinel))).toBe(sentinelHash);
function dispose(token: object) { expect(cleanupSyntheticFixture(token).status).toBe("CONFIRMED"); safe(); }
function observed(id: string, fn: () => void) { try { fn(); safe(); record(id, "PASS"); } catch (error) { record(id, "FAIL"); throw error; } }
afterAll(() => {
  safe();
  if (!process.env.ROUTECAIRN_A1_PROOF) throw Error("A1_PROOF_REQUIRED");
  const text = JSON.stringify({ schemaVersion: 1, syntheticOnly: true, platform: process.platform, node: process.version, sentinelUnchanged: true, sentinelSha256: sentinelHash, caseIdsUnique: new Set(cases.map((v: any) => v.id)).size === cases.length, cases, remainingEntries: readdirSync(parent).sort(), root: parent, originalOwnerCopied: 0, npm: false, network: false }) + "\n";
  expect(Buffer.byteLength(text)).toBeLessThan(LIMITS.outputBytes);
  appendFileSync(process.env.ROUTECAIRN_A1_PROOF, text);
});

describe("A1 pure fail-closed policy", () => {
  const badPaths = ["", "../x", "a/../x", "a/./x", "/tmp/x", "C:/x", "C:\\x", "//host/x", "\\\\host\\x", "x:stream", "%2e%2e/x", "%252e%252e/x", "x%2fy", "a\\b", "a//b", "a/", "x.", "x ", "CON", "nul.txt", "com0.txt", "COM9.bin", "lpt1", "aux", "prn.txt", ".git/config", ".npmrc", "x;y", "x&y", "x|y", "x$y", "x`y", "x(y)", "x<y", "x>y", "x*y", "x?y", "x\u0000y", "e\u0301.ts", "é.ts", "Ａ.ts", "a∕b", "a\ny", "x".repeat(241)];
  it.each(badPaths)("rejects ambiguous path %j", (name) => observed("PATH" + ++sequence, () => expect(() => portablePath(name)).toThrow(/A1_PATH/)));
  it("permits portable reviewed inputs, metadata and SDK paths", () => observed("PATH_GOOD", () => { for (const name of [".gitattributes", "src/a.ts", "standards/sources/cwe-4.20.xml.zip", "dist/core/plugins/ModuleSdk.d.ts"]) expect(portablePath(name)).toBe(name); }));
  it("rejects duplicate and case-folded names", () => observed("CASE_COLLISION", () => { expect(() => exactNames(["a.ts", "A.ts"], ["a.ts", "A.ts"])).toThrow(/COLLISION/); expect(() => exactNames(["a.ts", "a.ts"], ["a.ts", "a.ts"])).toThrow(); }));
  it.each(["extra", "missing", "modified", "size"])("rejects exact-manifest drift %s", (kind) => observed("MANIFEST_" + kind, () => {
    const files = [entry("a.ts"), entry("b.ts")]; const frozen = manifestDigest(files);
    if (kind === "extra") expect(() => exactNames([...files.map((v) => v.path), "c.ts"], files.map((v) => v.path))).toThrow();
    if (kind === "missing") expect(() => exactNames(["a.ts"], files.map((v) => v.path))).toThrow();
    if (kind === "modified") expect(manifestDigest([entry("a.ts", "other"), files[1]])).not.toBe(frozen);
    if (kind === "size") expect(manifestDigest([{ ...files[0], bytes: 6 }, files[1]])).not.toBe(frozen);
  }));
  it("uses deterministic content digests independent of enumeration", () => observed("DIGEST", () => expect(manifestDigest([entry("b"), entry("a")])).toBe(manifestDigest([entry("a"), entry("b")]))));
  it.each(["extra", "missing", "index", "remote", "head", "rename", "status", "untracked"])("rejects Git drift %s", (kind) => observed("GIT_" + kind, () => {
    const state: any = { head: PIN, main: PIN, originMain: PIN, remoteMain: PIN, index: [], tracked: ["a.ts"], status: [{ path: "a.ts", status: " M" }, { path: "b.ts", status: "??" }] };
    const changed = state.status.map((v: any) => ({ ...v }));
    if (kind === "extra") state.status.push({ path: "c.ts", status: "??" });
    if (kind === "missing") state.status.pop();
    if (kind === "index") state.index = ["a.ts"];
    if (kind === "remote") state.remoteMain = "a".repeat(40);
    if (kind === "head") state.head = "a".repeat(40);
    if (kind === "rename") state.status[0].path = "c.ts";
    if (kind === "status") state.status[0].status = "D ";
    if (kind === "untracked") state.tracked.push("z.ts");
    expect(() => assertGitState(state, changed, ["a.ts", "b.ts"])).toThrow(/A1_/);
  }));
  it("never turns a cached remote ref into live remote proof", () => observed("OFFLINE_REMOTE_HOLD", () => expect(assertGitState({ head: PIN, main: PIN, originMain: PIN, tracked: ["a"], status: [], index: [] }, [], ["a"]).liveRemote).toMatch(/^HOLD/)));
  it("refuses rename/status protocol ambiguity", () => observed("PORCELAIN", () => { expect(parseStatus(Buffer.from(" M a.ts\0?? b.ts\0"))).toHaveLength(2); expect(() => parseStatus(Buffer.from("R  a.ts\0b.ts\0"))).toThrow(); expect(() => parseStatus(Buffer.from(" M a.ts"))).toThrow(); }));
  it("proves finite transitive closure and refuses missing/protected input", () => observed("CLOSURE_TRANSITIVE", () => {
    const names = ["index.html", "src/a.ts", "src/b.ts", "asset.svg"];
    const edges = [{ from: "index.html", to: "src/a.ts" }, { from: "src/a.ts", to: "src/b.ts" }, { from: "src/b.ts", to: "asset.svg" }];
    expect(dependencyClosure(names, ["index.html"], edges).reached).toHaveLength(4);
    expect(() => dependencyClosure(names.slice(0, 3), ["index.html"], edges)).toThrow(/CLOSURE_MISSING/);
    expect(() => dependencyClosure(names, ["index.html"], [...edges, { from: "src/a.ts", to: "tests/protected.ts" }])).toThrow();
  }));
  it("checks real parser imports before script topology and refuses absent asset", () => observed("CLOSURE_AST", () => {
    const files = [entry("package.json", "{}"), entry("package-lock.json", '{"packages":{}}'), entry("npm-shrinkwrap.json", '{"packages":{}}'), entry("src/a.ts", 'import "./absent.ts";')];
    expect(() => analyzeBuildClosure({ buildInputs: files }, new Map(files.map((v) => [v.path, v.content.toString()])), ts)).toThrow(/CLOSURE_MISSING/);
    files[3] = entry("src/a.ts", 'const x = new URL("./absent.svg", import.meta.url);');
    expect(() => analyzeBuildClosure({ buildInputs: files }, new Map(files.map((v) => [v.path, v.content.toString()])), ts)).toThrow(/CLOSURE_RESOURCE_MISSING/);
  }));
  it("rejects divergent locks and unlocked dependencies", () => observed("CLOSURE_LOCK", () => {
    const files = [entry("package.json", "{}"), entry("package-lock.json", '{"packages":{}}'), entry("npm-shrinkwrap.json", '{"packages":{"changed":{}}}')];
    expect(() => analyzeBuildClosure({ buildInputs: files }, new Map(files.map((v) => [v.path, v.content.toString()])), ts)).toThrow(/LOCK_MISMATCH/);
    files[2] = files[1]; files[2] = { ...files[1], path: "npm-shrinkwrap.json" }; files.push(entry("src/a.ts", 'import "unknown-package";'));
    expect(() => analyzeBuildClosure({ buildInputs: files }, new Map(files.map((v) => [v.path, v.content.toString()])), ts)).toThrow(/UNLOCKED/);
  }));
  it("distinguishes a lexical owner-application require from a root dependency", () => observed("CLOSURE_BOUND_REQUIRE", () => {
    const files = [entry("package.json", '{"scripts":{}}'), entry("package-lock.json", '{"packages":{}}'), entry("npm-shrinkwrap.json", '{"packages":{}}'), entry("src/a.ts", 'import {createRequire} from "node:module"; function adapter(root:string) { const require=createRequire(root); return require("owner-only-dependency"); }')];
    expect(() => analyzeBuildClosure({ buildInputs: files }, new Map(files.map((v) => [v.path, v.content.toString()])), ts)).toThrow(/CLOSURE_SCRIPT_DRIFT/);
  }));
  it("still refuses an unbound require outside the lexical adapter scope", () => observed("CLOSURE_REQUIRE_SCOPE", () => {
    const files = [entry("package.json", '{}'), entry("package-lock.json", '{"packages":{}}'), entry("npm-shrinkwrap.json", '{"packages":{}}'), entry("src/a.ts", 'function adapter(root:string) { const require=createRequire(root); return require("owner"); } require("missing-root-dependency");')];
    expect(() => analyzeBuildClosure({ buildInputs: files }, new Map(files.map((v) => [v.path, v.content.toString()])), ts)).toThrow(/UNLOCKED/);
  }));
  it.each(["dist/a.js.map", "dist/a.d.ts", "dist/witness.json", "dist/session.json", "private/key.json", "src/x.ts", "dist/x.key", "tests/x.ts", "dist/x.sqlite", "dist/x.fixture.js"])("refuses malicious package path %s", (name) => observed("PACKAGE" + ++sequence, () => expect(() => packagePath(name, ["**"])).toThrow()));
  it("permits only the approved SDK declaration and checks both glob depths", () => observed("PACKAGE_GOOD", () => { expect(packagePath("dist/core/plugins/ModuleSdk.d.ts", ["dist/core/plugins/ModuleSdk.d.ts"])).toBeTruthy(); expect(packagePath("dist/a.js", ["dist/**/*.js"])).toBeTruthy(); expect(packagePath("dist/deep/a.js", ["dist/**/*.js"])).toBeTruthy(); }));
  it("rejects private provisioning content, hash mismatch and unsafe inclusion", () => observed("PACKAGE_CONTENT", () => {
    for (const text of ["-----BEGIN PRIVATE KEY-----", "function provisionFixtureWitness() {}", "FIXTURE_WITNESS_ALREADY_BOUND"]) expect(() => auditCandidate([entry("dist/a.js", text)], ["dist/**/*.js"])).toThrow(/PRIVATE_CONTENT/);
    expect(() => auditCandidate([{ ...entry("dist/a.js"), sha256: "0".repeat(64) }], ["dist/**/*.js"])).toThrow(/PACKAGE_BYTES/);
    expect(() => auditCandidate([entry("dist/a.js")], ["examples/**"])).toThrow(/ALLOWLIST/);
    expect(auditCandidate([entry("dist/a.js")], ["dist/**/*.js"]).internalExecuteFreshConflict).toBe("HOLD");
  }));
  it("keeps exact caps and conservative peak headroom", () => observed("CAPS", () => {
    expect(() => validateEntries([{ ...entry("a"), bytes: LIMITS.inputBytes + 1 }])).toThrow();
    expect(() => validateEntries(Array.from({ length: 1501 }, (_, i) => entry("a" + i)))).toThrow();
    expect(() => validateEntries(Array.from({ length: 1000 }, (_, i) => entry("a" + i)), "candidate")).toThrow();
    expect(() => validateEntries(Array.from({ length: 9 }, (_, i) => ({ ...entry("a" + i), bytes: LIMITS.inputBytes })))).toThrow(/BYTE_CAP/);
    expect(() => validateEntries([{ ...entry("a"), bytes: 8 * 1024 ** 2 }], "candidate")).toThrow(/BYTE_CAP/);
    expect(resourcePlan({ sourceBytes: 1000, dependencyBytes: 1000, freeBytes: LIMITS.freeBytes }).status).toBe("HOLD_HEADROOM");
    expect(resourcePlan({ sourceBytes: 1000, dependencyBytes: 1000, freeBytes: 8 * 1024 ** 3 }).peakBytes).toBeGreaterThan(LIMITS.freeBytes);
    expect(resourcePlan({ sourceBytes: 1000, dependencyBytes: 1000, freeBytes: 8 * 1024 ** 3 }).freeBytes).toBe(8 * 1024 ** 3);
    expect(() => resourcePlan({ sourceBytes: 1, dependencyBytes: -1, freeBytes: 9 })).toThrow();
  }));
  it("declares isolated paths with no inherited environment or owner fallback", () => observed("ENV", () => {
    const scratch = join(parent, "future-scratch"), runtime = join(parent, "approved-runtime"), original = join(parent, "owner");
    const plan = environmentPlan(scratch, runtime, [original]); expect(plan.inheritedEnvironment).toBe("NONE"); expect(plan.PATH).toBe(runtime);
    for (const key of ["HOME", "USERPROFILE", "NPM_CONFIG_CACHE", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG", "TEMP", "PLAYWRIGHT_BROWSERS_PATH", "ROUTECAIRN_DASHBOARD_DIR"]) expect(plan[key]).toContain(scratch);
    expect(() => environmentPlan(join(original, "scratch"), runtime, [original])).toThrow(/FALLBACK/);
    expect(() => environmentPlan(scratch, original, [original])).toThrow(/FALLBACK/);
    expect(existsSync(scratch)).toBe(false);
  }));
});

describe("A1 test-owned physical isolation and identity", () => {
  it("copies two small files physically, verifies provenance, and preserves original on edit", () => observed("COPY_PHYSICAL", () => {
    const source = fresh(), copy = copySyntheticFixture(source, parent), a = fixtureFacts(source), b = fixtureFacts(copy);
    expect(a.rootIdentity.ino).not.toBe(b.rootIdentity.ino); expect(verifySyntheticFixture(copy)).toHaveLength(2);
    for (let i = 0; i < a.entries.length; i++) expect(a.entries[i].currentIdentity.ino).not.toBe(b.entries[i].currentIdentity.ino);
    writeFileSync(join(b.root, "src/a.ts"), "edited owned copy"); expect(() => verifySyntheticFixture(copy)).toThrow(); expect(verifySyntheticFixture(source)).toHaveLength(2); dispose(copy); dispose(source);
  }));
  it("rejects arbitrary-owner copy and excessive fixtures", () => observed("COPY_CAPABILITY", () => {
    expect(() => copySyntheticFixture({ root: resolve(".") }, parent)).toThrow(/OWNERSHIP/);
    expect(() => createSyntheticFixture(parent, Array.from({ length: 609 }, (_, i) => ({ path: "a" + i, content: Buffer.from("x") })))).toThrow(/SYNTHETIC_ONLY/);
    expect(() => createSyntheticFixture(parent, [{ path: "a", content: Buffer.alloc(4097) }, tiny()[1]])).toThrow(/SYNTHETIC_ONLY/);
  }));
  it("detects replaced destination identity even with identical bytes", () => observed("COPY_REPLACEMENT", () => {
    const source = fresh(), copy = copySyntheticFixture(source, parent), facts = fixtureFacts(copy), file = join(facts.root, "src/a.ts");
    renameSync(file, join(facts.root, "src/held.ts")); writeFileSync(file, tiny()[0].content, { flag: "wx" });
    expect(() => verifySyntheticFixture(copy)).toThrow(/IDENTITY_CHANGED/); expect(verifySyntheticFixture(source)).toHaveLength(2); dispose(copy); dispose(source);
  }));
  it("detects source churn and bounded read overflow", () => observed("READ_CHURN", () => {
    const token = fresh(), facts = fixtureFacts(token), capture = captureRoot(facts.root), old = readBounded(capture, "src/a.ts");
    writeFileSync(join(facts.root, "src/a.ts"), "modified"); expect(() => readBounded(capture, "src/a.ts", old.identity)).toThrow(/IDENTITY_CHANGED/);
    expect(() => verifyEntries(capture, facts.entries)).toThrow(); expect(() => readBounded(capture, "src/a.ts", undefined, 1)).toThrow(/CAP/); dispose(token);
  }));
  it("refuses root identity substitution", () => observed("ROOT_SWAP", () => {
    const token = fresh(), facts = fixtureFacts(token); renameSync(facts.root, facts.root + "-held"); mkdirSync(facts.root);
    expect(() => verifySyntheticFixture(token)).toThrow(/PARENT_IDENTITY/); expect(() => cleanupSyntheticFixture(token)).toThrow();
    rmdirSync(facts.root); renameSync(facts.root + "-held", facts.root); dispose(token);
  }));
  it("refuses approved-parent substitution", () => observed("PARENT_SWAP", () => {
    const sub = mkdtempSync(join(parent, "parent-")), token = createSyntheticFixture(sub, tiny()); renameSync(sub, sub + "-held"); mkdirSync(sub);
    expect(() => verifySyntheticFixture(token)).toThrow(/PARENT_IDENTITY/); rmdirSync(sub); renameSync(sub + "-held", sub); dispose(token); rmdirSync(sub);
  }));
  it.each(["hardlink", "junction", "symlink"])("attempts real native %s with honest BLOCKED accounting", (kind) => {
    const token = fresh(), facts = fixtureFacts(token), alias = join(facts.root, "native-alias");
    try {
      try {
        if (kind === "hardlink") linkSync(join(facts.root, "src/a.ts"), alias);
        else symlinkSync(kind === "junction" ? join(facts.root, "src") : join(facts.root, "src/a.ts"), alias, kind === "junction" ? "junction" : "file");
      } catch (error: any) {
        if (!["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) throw error;
        record("NATIVE_" + kind, "BLOCKED", { nativeCapability: true, reason: error.code, elevated: false }); return;
      }
      expect(() => readBounded(captureRoot(facts.root), "native-alias")).toThrow();
      expect(() => planCleanup(token)).toThrow(/LINK_DEVICE/);
      if (kind === "hardlink") expect(() => verifySyntheticFixture(token)).toThrow();
      record("NATIVE_" + kind, "PASS", { nativeCapability: true, originalInodeAliasDenied: kind === "hardlink" });
    } catch (error) { record("NATIVE_" + kind, "FAIL"); throw error; }
    finally { if (existsSync(alias) || (() => { try { return lstatSync(alias).isSymbolicLink(); } catch { return false; } })()) { if (kind === "junction" && process.platform === "win32") rmdirSync(alias); else unlinkSync(alias); } dispose(token); }
  });
});

describe("A1 bounded nonrecursive cleanup", () => {
  it("plans the whole tree, cleans exact ownership, then refuses replay", () => observed("CLEANUP_COMPLETE", () => {
    const token = fresh(), facts = fixtureFacts(token), plan = planCleanup(token); expect(plan.completeBeforeDeletion).toBe(true); expect(plan.entries).toHaveLength(5);
    dispose(token); expect(existsSync(facts.root)).toBe(false); expect(() => cleanupSyntheticFixture(token)).toThrow(/OWNERSHIP/);
  }));
  it("refuses unknown roots and copied ownership claims", () => observed("CLEANUP_UNKNOWN", () => {
    expect(() => cleanupSyntheticFixture({ root: parent })).toThrow(/OWNERSHIP/); const token = fresh(); expect(() => cleanupSyntheticFixture({ ...fixtureFacts(token) })).toThrow(); dispose(token);
  }));
  it("denies wrong marker before deleting any file", () => observed("CLEANUP_MARKER", () => {
    const token = fresh(), facts = fixtureFacts(token), marker = join(facts.root, "A1_OWNERSHIP"), old = readFileSync(marker); writeFileSync(marker, "wrong marker");
    expect(() => cleanupSyntheticFixture(token)).toThrow(/MARKER/); expect(existsSync(join(facts.root, "src/a.ts"))).toBe(true);
    writeFileSync(marker, old); dispose(token);
  }));
  it.each(["entries", "depth", "bytes"])("refuses cleanup %s cap before deletion", (kind) => observed("CLEANUP_CAP_" + kind, () => {
    const token = fresh(), facts = fixtureFacts(token);
    if (kind === "entries") for (let i = 0; i < 512; i++) writeFileSync(join(facts.root, "x" + i), "x", { flag: "wx" });
    if (kind === "depth") { let p = facts.root; for (let i = 0; i < 13; i++) { p = join(p, "d"); mkdirSync(p); } }
    if (kind === "bytes") { const fdPath = join(facts.root, "oversized"); writeFileSync(fdPath, Buffer.alloc(1)); truncateSync(fdPath, LIMITS.cleanupBytes + 1); }
    expect(() => cleanupSyntheticFixture(token)).toThrow(/(?:CLEANUP_(?:BYTE_)?CAP|DIRECTORY_ENTRY_CAP)/); expect(existsSync(join(facts.root, "src/a.ts"))).toBe(true);
    record("RETAINED_" + kind, "PASS", { disposition: "EXPECTED_DENIAL_OWNED_OVERRUN_RETAINED_NO_DELETE", syntheticOnly: true });
  }));
  it("retains partial injected failure and never retries a retained capability", () => observed("CLEANUP_PARTIAL", () => {
    const token = fresh(), facts = fixtureFacts(token);
    const result = cleanupSyntheticFixture(token, (removed: number) => { if (removed === 1) throw Error("synthetic interruption"); });
    expect(result.status).toBe("RETAINED_INCOMPLETE"); expect(result.removed).toBe(1); expect(existsSync(join(facts.root, "A1_OWNERSHIP"))).toBe(true); expect(() => cleanupSyntheticFixture(token)).toThrow(/OWNERSHIP/);
    record("PARTIAL_RETENTION", "PASS", { cleanup: result });
  }));
  it("denies last-moment parent replacement before unlink", () => observed("CLEANUP_PARENT_RACE", () => {
    const token = fresh(), facts = fixtureFacts(token);
    const result = cleanupSyntheticFixture(token, (_removed: number, path: string) => { if (path === "assets/b.json") { renameSync(join(facts.root, "assets"), join(facts.root, "held-assets")); mkdirSync(join(facts.root, "assets")); writeFileSync(join(facts.root, "assets/b.json"), "replacement", { flag: "wx" }); } });
    expect(result.status).toBe("RETAINED_INCOMPLETE"); expect(readFileSync(join(facts.root, "assets/b.json"), "utf8")).toBe("replacement");
  }));
  it("refuses last-moment target replacement and preserves the replacement", () => observed("CLEANUP_TARGET_RACE", () => {
    const token = fresh(), facts = fixtureFacts(token);
    const result = cleanupSyntheticFixture(token, (_removed: number, path: string) => { if (path === "assets/b.json") { renameSync(join(facts.root, path), join(facts.root, "held.json")); writeFileSync(join(facts.root, path), "replacement", { flag: "wx" }); } });
    expect(result.status).toBe("RETAINED_INCOMPLETE"); expect(result.reason).toBe("A1_CLEANUP_IDENTITY_CHANGED"); expect(readFileSync(join(facts.root, "assets/b.json"), "utf8")).toBe("replacement");
  }));
  it("refuses unexpected entries at marker deletion", () => observed("CLEANUP_LATE_ENTRY", () => {
    const token = fresh(), facts = fixtureFacts(token);
    const result = cleanupSyntheticFixture(token, (_removed: number, path: string) => { if (path === "A1_OWNERSHIP") writeFileSync(join(facts.root, "late"), "retained", { flag: "wx" }); });
    expect(result.status).toBe("RETAINED_INCOMPLETE"); expect(existsSync(join(facts.root, "A1_OWNERSHIP"))).toBe(true);
  }));
});

describe("A1 explicit read-only command boundary", () => {
  it.each([[], ["--copy"], ["--pack"], ["--install"], ["--plan", "--verify"], ["--plan", "--repo", "."], ["--plan", "--output", "x"]].map((args) => ({ args })))("rejects missing/unknown/mutating argv $args", ({ args }) => observed("ARGV" + ++sequence, () => expect(() => parseArguments(args)).toThrow(/A1_/)));
  it.each(["--plan", "--verify"])("attempts %s against a tiny synthetic fixture without writes or subprocess lifecycle", (mode) => observed("CLI_" + mode, () => {
    const token = fresh(), facts = fixtureFacts(token), before = verifySyntheticFixture(token), invalid = join(facts.root, "assets/b.json");
    const run = spawnSync(process.execPath, [resolve("scripts/safe-release-preflight.mjs"), mode, "--repo", facts.root, "--baseline", invalid, "--original-review", invalid, "--review-inputs", invalid, "--review-sha256", digest(readFileSync(invalid))], { encoding: "utf8", windowsHide: true, timeout: 5000, maxBuffer: LIMITS.outputBytes, env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot } });
    expect(run.status).toBe(1); expect(JSON.parse(run.stderr).reason).toBe("A1_MANIFEST_DIGEST"); expect(run.stdout).toBe(""); expect(verifySyntheticFixture(token)).toEqual(before); expect(planCleanup(token).entries).toHaveLength(5); dispose(token);
  }));
  it("keeps the read-only dispatch free of copy, network and lifecycle launchers", () => observed("CLI_STATIC_BOUNDARY", () => {
    const source = readFileSync(resolve("scripts/safe-release-preflight.mjs"), "utf8"), ast = ts.createSourceFile("preflight.mjs", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS), calls: string[] = [];
    function visit(n: ts.Node) { if (ts.isCallExpression(n)) calls.push(n.expression.getText(ast)); ts.forEachChild(n, visit); } visit(ast);
    for (const name of ["spawn", "spawnSync", "copyFileSync", "copySyntheticFixture", "createSyntheticFixture", "fetch", "request", "mkdirSync", "writeFileSync", "unlinkSync", "rmSync"]) expect(calls).not.toContain(name);
    expect(A1_PATHS).toHaveLength(4); expect(source).not.toMatch(/execFileSync\("(?:npm|npm.cmd|powershell|cmd|sh)"/);
  }));
});

// A1B: additive regressions. Existing 109 assertions above are unchanged.
import * as structural from "../../scripts/safe-release-isolation.mjs";
const a1bCases: object[] = [];
function a1bRecord(id: string, status: string, facts: object = {}) { a1bCases.push({ id, status, ...facts }); }
function largeFixture(profile: string) {
  const api = structural as any;
  if (typeof api.createStructuralSyntheticFixture === "function") return { token: api.createStructuralSyntheticFixture(parent, profile, "A1B_SYNTHETIC_PROPOSAL_V1"), native: true };
  // RED baseline: the original tiny opaque owner can hold generated files but
  // its complete-tree planner refuses >512 before removing anything.
  const token = createSyntheticFixture(parent, [{ path: "d000/f0000.txt", content: Buffer.from("A1B generated 0\n") }, { path: "d001/f0001.txt", content: Buffer.from("A1B generated 1\n") }]);
  const root = fixtureFacts(token).root, count = profile === "files609" ? 609 : 750;
  for (let i = 2; i < count; i++) { const dir = join(root, "d" + String(i % 124).padStart(3, "0")); if (!existsSync(dir)) mkdirSync(dir); writeFileSync(join(dir, "f" + String(i).padStart(4, "0") + ".txt"), "A1B generated " + i + "\n", { flag: "wx" }); }
  return { token, native: false };
}
afterAll(() => {
  safe(); if (!process.env.ROUTECAIRN_A1B_PROOF) throw Error("A1B_PROOF_REQUIRED");
  const proof = { schemaVersion: 1, syntheticOnly: true, machine: { platform: process.platform, node: process.version }, sentinelUnchanged: digest(readFileSync(sentinel)) === sentinelHash, cases: a1bCases, ownerTreeCopied: false, npm: false, productionExecution: false };
  const text = JSON.stringify(proof) + "\n"; expect(Buffer.byteLength(text)).toBeLessThan(LIMITS.outputBytes); appendFileSync(process.env.ROUTECAIRN_A1B_PROOF, text);
});
describe("A1B structural regressions", () => {
  it("validates all609 files plus dirs marker and root before deleting", () => {
    const f = largeFixture("files609");
    try {
      const plan = f.native ? (structural as any).planStructuralCleanup(f.token) : planCleanup(f.token);
      expect(plan.entries).toHaveLength(735); expect(plan.completeBeforeDeletion).toBe(true);
      if (f.native) expect((structural as any).cleanupStructuralFixture(f.token).status).toBe("CONFIRMED");
      a1bRecord("REGRESSION_609", "PASS", { entries: 735 });
    } catch (error) { a1bRecord("REGRESSION_609", "FAIL", { reason: (error as Error).message, residueRetained: true }); throw error; }
  });
  it("predetermines bounded batches for750 synthetic files without raising512", () => {
    const f = largeFixture("files750");
    try {
      const plan = f.native ? (structural as any).planStructuralCleanup(f.token) : planCleanup(f.token);
      expect(plan.entries).toHaveLength(876); expect(plan.batches.map((v: number[]) => v.length)).toEqual([512, 364]); expect(LIMITS.cleanupEntries).toBe(512);
      if (f.native) expect((structural as any).cleanupStructuralFixture(f.token).status).toBe("CONFIRMED");
      a1bRecord("REGRESSION_750", "PASS", { entries: 876, batches: [512, 364] });
    } catch (error) { a1bRecord("REGRESSION_750", "FAIL", { reason: (error as Error).message, residueRetained: true }); throw error; }
  });
});

const bapi = structural as any;
function bfixture(profile = "entries511") { const token = bapi.createStructuralSyntheticFixture(parent, profile, "A1B_SYNTHETIC_PROPOSAL_V1"); return { token, ...bapi.structuralFixtureFacts(token) }; }
function bobserved(id: string, action: () => object | void) {
  try { const facts = action() || {}; safe(); a1bRecord(id, "PASS", facts); }
  catch (error) { a1bRecord(id, "FAIL", { reason: /^A1B?_[A-Z_]+$/.test((error as Error).message) ? (error as Error).message : "ASSERTION_OR_NATIVE_FAILURE" }); throw error; }
}
function bretained(f: any, hooks = {}) {
  const result = bapi.cleanupStructuralFixture(f.token, hooks); expect(result.status).toBe("RETAINED_INCOMPLETE"); expect(result.automaticRetry).toBe(false); expect(existsSync(f.root)).toBe(true); expect(() => bapi.cleanupStructuralFixture(f.token)).toThrow(/CAPABILITY_STATE/); safe(); return result;
}
describe("A1B complete immutable global plan", () => {
  it.each([511, 512, 513])("counts root and marker at exactly%i members", (count) => bobserved("BOUNDARY_" + count, () => {
    const f = bfixture("entries" + count), plan = bapi.planStructuralCleanup(f.token);
    expect(plan.entries).toHaveLength(count); expect(plan.entries.filter((e: any) => e.kind === "root")).toHaveLength(1); expect(plan.entries.filter((e: any) => e.kind === "marker")).toHaveLength(1);
    expect(plan.batches.every((b: number[]) => b.length <= 512)).toBe(true); if (count === 513) expect(plan.batches.map((b: number[]) => b.length)).toEqual([511, 2]);
    const order: string[] = [], result = bapi.cleanupStructuralFixture(f.token, { beforeDelete: ({ member }: any) => { order.push(member.kind); } });
    expect(result.status).toBe("CONFIRMED"); expect(result.removed).toBe(count); expect(order.slice(-2)).toEqual(["marker", "root"]); expect(existsSync(f.root)).toBe(false); expect(() => bapi.cleanupStructuralFixture(f.token)).toThrow();
    return { entries: count, batchSizes: result.batchSizes, removed: result.removed, rootAbsent: true };
  }));
  it("retains the exact609 global inventory and batch coverage proof", () => bobserved("GLOBAL_PLAN_PROOF", () => {
    const f = bfixture("files609"), plan = bapi.planStructuralCleanup(f.token); expect(plan.files).toBe(609); expect(plan.directories).toBe(124); expect(plan.entries).toHaveLength(735);
    expect(bapi.validateStructuralSchedule(plan).deletionAuthority).toBe(false); expect(JSON.stringify(plan)).not.toContain(f.root); expect(JSON.stringify(plan)).not.toContain(readFileSync(join(f.root, "A1B_OWNERSHIP"), "utf8"));
    if (!process.env.ROUTECAIRN_A1B_ARTIFACTS) throw Error("A1B_ARTIFACTS_REQUIRED"); writeFileSync(join(process.env.ROUTECAIRN_A1B_ARTIFACTS, "synthetic735-plan.json"), JSON.stringify(plan, null, 2), { flag: "wx" });
    // A detached plan can be poisoned without altering the private frozen plan.
    plan.batches[0].reverse(); const result = bapi.cleanupStructuralFixture(f.token); expect(result.status).toBe("CONFIRMED"); expect(result.batchSizes).toEqual([512, 223]); return result;
  }));
  it.each(["wide", "duplicate", "missing", "postorder", "marker", "generation", "identity", "case", "traversal", "depth"])("rejects an invalid detached schedule:%s", (attack) => bobserved("SCHEDULE_" + attack, () => {
    const f = bfixture(), plan = bapi.planStructuralCleanup(f.token), bad = structuredClone(plan);
    if (attack === "wide") bad.batches = [[...bad.batches[0], bad.batches[0][0], bad.batches[0][0]]];
    if (attack === "duplicate") bad.batches[0][0] = bad.batches[0][1];
    if (attack === "missing") bad.batches[0].shift();
    if (attack === "postorder") [bad.batches[0][0], bad.batches[0][500]] = [bad.batches[0][500], bad.batches[0][0]];
    if (attack === "marker") bad.batches[0].reverse();
    if (attack === "generation") bad.generationSha256 = "invalid";
    if (attack === "identity") delete bad.entries[2].identity;
    if (attack === "case") bad.entries[3].path = bad.entries[2].path.toUpperCase();
    if (attack === "traversal") bad.entries[2].path = "../outside";
    if (attack === "depth") bad.entries[2].path = "a/b/c/d/e/f";
    expect(() => bapi.validateStructuralSchedule(bad)).toThrow(); const result = bapi.cleanupStructuralFixture(f.token); expect(result.status).toBe("CONFIRMED"); return { detachedPlanRefused: true, originalCapabilityNotAltered: true };
  }));
  it("requires explicit synthetic opt-in, rejects adoption, and preserves tiny API limits", () => bobserved("NO_ADOPTION_OR_COPY", () => {
    expect(() => bapi.createStructuralSyntheticFixture(parent, "files609", "approved")).toThrow(); expect(() => bapi.createStructuralSyntheticFixture(parent, { files: 609 }, "A1B_SYNTHETIC_PROPOSAL_V1")).toThrow();
    expect(() => bapi.createStructuralSyntheticFixture("\\\\host\\share", "files609", "A1B_SYNTHETIC_PROPOSAL_V1")).toThrow(); expect(() => bapi.cleanupStructuralFixture({ root: parent })).toThrow();
    expect(() => createSyntheticFixture(parent, Array.from({ length: 609 }, (_, i) => ({ path: "f" + i, content: Buffer.from("constant") })))).toThrow(/SYNTHETIC_ONLY/);
    expect(LIMITS.cleanupEntries).toBe(512); expect(LIMITS.cleanupBytes).toBe(64 * 1024 ** 2); expect(LIMITS.cleanupDepth).toBe(12); expect(bapi.STRUCTURAL_CLEANUP_PROPOSAL.realUseAuthorized).toBe(false);
  }));
});

describe("A1B zero-delete global refusals", () => {
  it.each(["aggregate", "bytes", "depth", "single", "fanout", "extra", "missing", "rename", "case"])("denies global violation before first delete:%s", (attack) => bobserved("PREFLIGHT_" + attack, () => {
    const f = bfixture(attack === "aggregate" ? "files750" : "entries511"), limit = bapi.STRUCTURAL_CLEANUP_PROPOSAL;
    if (attack === "aggregate" || attack === "extra") writeFileSync(join(f.root, "d000/extra.txt"), "unplanned", { flag: "wx" });
    if (attack === "single") truncateSync(join(f.root, "d000/f0000.txt"), limit.singleFileBytes + 1);
    if (attack === "bytes") {
      const initial = Array.from({ length: 385 }, (_, i) => Buffer.byteLength("A1B generated " + i + "\n")).reduce((a, b) => a + b, 36), old = [0, 1, 2, 3].reduce((s, i) => s + Buffer.byteLength("A1B generated " + i + "\n"), 0);
      let remain = limit.bytes + 1 - (initial - old);
      for (let i = 0; i < 4; i++) { const n = Math.min(limit.singleFileBytes, remain); truncateSync(join(f.root, "d" + String(i).padStart(3, "0"), "f" + String(i).padStart(4, "0") + ".txt"), n); remain -= n; } expect(remain).toBe(0);
    }
    if (attack === "depth") { let p = join(f.root, "d000"); for (let i = 0; i < 5; i++) { p = join(p, "z"); mkdirSync(p); } }
    if (attack === "fanout") for (let i = 0; i < 126; i++) writeFileSync(join(f.root, "d000/x" + i), "x", { flag: "wx" });
    if (attack === "missing") unlinkSync(join(f.root, "d000/f0000.txt"));
    if (attack === "rename") renameSync(join(f.root, "d000/f0000.txt"), join(f.root, "d000/renamed.txt"));
    if (attack === "case") renameSync(join(f.root, "d000/f0000.txt"), join(f.root, "d000/F0000.txt"));
    const result = bretained(f); expect(result.removed).toBe(0); expect(existsSync(join(f.root, "A1B_OWNERSHIP"))).toBe(true);
    if (attack === "aggregate") expect(result.reason).toMatch(/GLOBAL_COUNT/); if (attack === "bytes") expect(result.reason).toBe("A1B_GLOBAL_BYTE_CAP"); if (attack === "single") expect(result.reason).toBe("A1B_SINGLE_FILE_CAP"); return result;
  }));
  it("denies stolen marker and never adopts a copied capability", () => bobserved("STOLEN_MARKER", () => {
    const a = bfixture(), b = bfixture(); writeFileSync(join(a.root, "A1B_OWNERSHIP"), readFileSync(join(b.root, "A1B_OWNERSHIP")));
    expect(() => bapi.cleanupStructuralFixture({ ...bapi.structuralFixtureFacts(b.token) })).toThrow(); expect(JSON.stringify(b.token)).toBe("{}"); const result = bretained(a); expect(result.removed).toBe(0);
    expect(bapi.cleanupStructuralFixture(b.token).status).toBe("CONFIRMED"); return result;
  }));
  it.each(["root", "parent"])("refuses identity substitution:%s", (attack) => bobserved("IDENTITY_" + attack, () => {
    const f = bfixture(); bapi.planStructuralCleanup(f.token);
    const path = attack === "root" ? f.root : join(f.root, "d000"); renameSync(path, path + "-held"); mkdirSync(path);
    const result = bretained(f); expect(result.removed).toBe(0); expect(existsSync(path + "-held")).toBe(true); return result;
  }));
});

describe("A1B irreversible partial failure and batch boundaries", () => {
  it.each([0, 7, 512, 520, 874, 875])("retires without implicit resume after exactly%i confirmed removals", (stop) => bobserved("FAULT_AFTER_" + stop, () => {
    const f = bfixture("files750"), plan = bapi.planStructuralCleanup(f.token); if (stop === 0) { if (!process.env.ROUTECAIRN_A1B_ARTIFACTS) throw Error("A1B_ARTIFACTS_REQUIRED"); writeFileSync(join(process.env.ROUTECAIRN_A1B_ARTIFACTS, "synthetic876-plan.json"), JSON.stringify(plan, null, 2), { flag: "wx" }); }
    const result = bretained(f, { beforeDelete: ({ removed }: any) => { if (removed === stop) throw Error("simulated operation failure"); } });
    expect(result.removed).toBe(stop); expect(result.batchesCompleted).toBe(stop >= 512 ? 1 : 0); expect(existsSync(join(f.root, "A1B_OWNERSHIP"))).toBe(stop < 875); expect(result.status).not.toBe("CONFIRMED"); return { ...result, simulated: true };
  }));
  it("detects a replacement between planning and first unlink", () => bobserved("REPLACE_AFTER_PLAN", () => {
    const f = bfixture(); bapi.planStructuralCleanup(f.token); renameSync(join(f.root, "d000/f0000.txt"), join(f.root, "d000/held.txt")); writeFileSync(join(f.root, "d000/f0000.txt"), "replacement", { flag: "wx" });
    const result = bretained(f); expect(result.removed).toBe(0); expect(readFileSync(join(f.root, "d000/f0000.txt"), "utf8")).toBe("replacement"); return result;
  }));
  it("refuses a changed remaining directory between batches without chasing it", () => bobserved("BETWEEN_BATCH_REPLACEMENT", () => {
    const f = bfixture("files750"), plan = bapi.planStructuralCleanup(f.token), remaining = plan.batches[1].map((id: number) => plan.entries[id]).find((e: any) => e.kind === "directory");
    const result = bretained(f, { beforeBatch: ({ batchIndex }: any) => { if (batchIndex === 1) { renameSync(join(f.root, remaining.path), join(f.root, remaining.path + "-held")); mkdirSync(join(f.root, remaining.path)); } } });
    expect(result.removed).toBe(512); expect(result.batchesCompleted).toBe(1); return result;
  }));
  it("retains an unplanned file added after512 deletions", () => bobserved("LATE_UNKNOWN_FILE", () => {
    const f = bfixture("files750");
    const result = bretained(f, { beforeBatch: ({ batchIndex }: any) => { if (batchIndex === 1) writeFileSync(join(f.root, "unplanned.txt"), "outside-plan", { flag: "wx" }); } });
    expect(result.removed).toBe(512); expect(readFileSync(join(f.root, "unplanned.txt"), "utf8")).toBe("outside-plan"); return result;
  }));
  it("rechecks the target and all parents immediately before native deletion", () => bobserved("BEFORE_NATIVE_REPLACEMENT", () => {
    const f = bfixture(), plan = bapi.planStructuralCleanup(f.token), first = plan.entries[plan.batches[0][0]];
    const result = bretained(f, { beforeDelete: ({ removed }: any) => { if (removed === 0) { renameSync(join(f.root, first.path), join(f.root, "held.txt")); writeFileSync(join(f.root, first.path), "replacement", { flag: "wx" }); } } });
    expect(result.removed).toBe(0); expect(readFileSync(join(f.root, first.path), "utf8")).toBe("replacement"); return result;
  }));
});

describe("A1B actual native link attempts", () => {
  it.each(["hardlink", "junction", "symlink"])("rejects a native%s or records BLOCKED without privilege changes", (kind) => {
    const f = bfixture(), alias = join(f.root, "native-alias"); let linked = false;
    try {
      try { if (kind === "hardlink") linkSync(sentinel, alias); else symlinkSync(kind === "junction" ? join(f.root, "d000") : sentinel, alias, kind === "junction" ? "junction" : "file"); linked = true; }
      catch (error: any) {
        if (!["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) throw error;
        // A denied native operation can still change parent metadata. Never
        // refresh the capability or assume the tree is pristine after failure.
        const disposition = bapi.cleanupStructuralFixture(f.token);
        if (disposition.status === "CONFIRMED") expect(existsSync(f.root)).toBe(false);
        else { expect(disposition.status).toBe("RETAINED_INCOMPLETE"); expect(disposition.removed).toBe(0); expect(disposition.automaticRetry).toBe(false); expect(existsSync(f.root)).toBe(true); expect(() => bapi.cleanupStructuralFixture(f.token)).toThrow(/CAPABILITY_STATE/); }
        a1bRecord("NATIVE_" + kind, "BLOCKED", { nativeCapability: true, reason: error.code, elevated: false, postAttemptDisposition: disposition }); return;
      }
      const result = bretained(f); expect(result.removed).toBe(0); a1bRecord("NATIVE_" + kind, "PASS", { nativeCapability: true, outsideSentinelUnchanged: true, removed: 0 });
    } catch (error) { a1bRecord("NATIVE_" + kind, "FAIL"); throw error; }
    finally { if (linked) { if (kind === "junction" && process.platform === "win32") rmdirSync(alias); else unlinkSync(alias); } safe(); }
  });
});

describe("A1B read-only real-source recognition", () => {
  it("accepts frozen D0/current A1B hashes and refuses tampering without writing sources", () => bobserved("SOURCE_HASH_RECOGNITION", () => {
    if (!process.env.ROUTECAIRN_A1B_BASELINE || !process.env.ROUTECAIRN_A1B_CURRENT) throw Error("A1B_SOURCE_MANIFESTS_REQUIRED");
    const frozen = JSON.parse(readFileSync(process.env.ROUTECAIRN_A1B_BASELINE, "utf8")), current = JSON.parse(readFileSync(process.env.ROUTECAIRN_A1B_CURRENT, "utf8")), cap = captureRoot(resolve("."));
    const d0 = frozen.changed.filter((e: any) => !A1_PATHS.includes(e.path)); expect(d0).toHaveLength(14); expect(verifyEntries(cap, d0)).toHaveLength(14); expect(verifyEntries(cap, current)).toHaveLength(4);
    expect(() => verifyEntries(cap, [{ ...d0[0], sha256: "0".repeat(64) }])).toThrow(/SOURCE_HASH/);
    const originalA1 = frozen.changed.find((e: any) => e.path === "scripts/safe-release-isolation.mjs"), bytes = readFileSync(resolve(originalA1.path)); expect(digest(bytes.subarray(0, originalA1.bytes))).toBe(originalA1.sha256);
    const originalTests = frozen.changed.find((e: any) => e.path === "tests/unit/safe-release-isolation.test.ts"); expect(digest(readFileSync(resolve(originalTests.path)).subarray(0, originalTests.bytes))).toBe(originalTests.sha256);
    expect(() => verifyEntries(cap, [originalA1])).toThrow(/SOURCE_HASH|IDENTITY_CHANGED/); return { d0: 14, currentA1B: 4, originalA1PrefixPreserved: true, original109TestPrefixPreserved: true, negativeHashDenied: true, sourceWrites: 0 };
  }));
});

import { spawn as spawnShareLock } from "node:child_process";
it("A1B refuses an actually unreadable Windows share-locked generated member", async () => {
  if (process.platform !== "win32") { a1bRecord("UNREADABLE_MEMBER", "BLOCKED", { nativeCapability: true, reason: "WINDOWS_SHARE_LOCK_PROFILE_REQUIRED" }); return; }
  const f = bfixture(), powershell = join(process.env.SystemRoot || "C:\\Windows", "System32/WindowsPowerShell/v1.0/powershell.exe"), file = join(f.root, "d000/f0000.txt");
  const script = "$ErrorActionPreference='Stop';$f=[IO.File]::Open('" + file.replaceAll("'", "''") + "',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);try{[Console]::Out.WriteLine('A1B_LOCKED');[Console]::Out.Flush();[void][Console]::ReadLine()}finally{$f.Dispose()}";
  const child = spawnShareLock(powershell, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { windowsHide: true, env: { SystemRoot: process.env.SystemRoot, PATH: process.env.PATH, TEMP: process.env.TEMP, TMP: process.env.TMP }, stdio: ["pipe", "pipe", "pipe"] });
  let closed = false, output = "", stderrBytes = 0; const close = new Promise<void>((done) => child.once("close", () => { closed = true; done(); })); child.stderr.on("data", (b) => { stderrBytes += b.length; if (stderrBytes > 8192) child.kill(); });
  try {
    await new Promise<void>((done, reject) => { const timeout = setTimeout(() => reject(Error("A1B_SHARE_LOCK_DEADLINE")), 6000); child.stdout.on("data", (b) => { output += b.toString(); if (output.includes("A1B_LOCKED")) { clearTimeout(timeout); done(); } if (output.length > 8192) { clearTimeout(timeout); reject(Error("A1B_SHARE_LOCK_OUTPUT_CAP")); } }); child.once("error", (e) => { clearTimeout(timeout); reject(e); }); child.once("close", (code) => { clearTimeout(timeout); if (!output.includes("A1B_LOCKED")) reject(Object.assign(Error("A1B_SHARE_LOCK_STARTUP"), { code: "NATIVE_STARTUP", exit: code })); }); });
    const result = bretained(f); expect(result.removed).toBe(0); a1bRecord("UNREADABLE_MEMBER", "PASS", { nativeCapability: true, actualShareNoneLock: true, removed: 0, refusal: result.reason });
  } catch (error: any) {
    if (["EPERM", "EACCES", "ENOENT", "NATIVE_STARTUP"].includes(error.code)) { a1bRecord("UNREADABLE_MEMBER", "BLOCKED", { nativeCapability: true, reason: error.code, exit: error.exit }); }
    else { a1bRecord("UNREADABLE_MEMBER", "FAIL", { reason: "HANDSHAKE_OR_ASSERTION_FAILURE" }); throw error; }
  } finally { if (!closed) child.stdin.end("release\n"); const deadline = setTimeout(() => child.kill(), 3000); await close; clearTimeout(deadline); safe(); }
});

// Nested follow-on: every previous153 test byte above stays unchanged.
const nestedCases: object[] = [];
const nestedTemplatePath = process.env.ROUTECAIRN_NESTED_TEMPLATE;
if (!nestedTemplatePath) throw Error("NESTED_FROZEN_TEMPLATE_REQUIRED");
const nestedTemplate = JSON.parse(readFileSync(nestedTemplatePath, "utf8"));
if (digest(JSON.stringify(nestedTemplate.directoryNames)) !== "c78542985009c6e2d47744c4aa47150a96b34914d8dc80772039d949011e1d64") throw Error("NESTED_TEMPLATE_PIN");
function nestedRecord(id: string, status: string, facts: object = {}) { nestedCases.push({ id, status, ...facts }); }
function nestedObserve(id: string, run: () => object) {
  try { const result = run(); safe(); nestedRecord(id, "PASS", result); }
  catch (error) { nestedRecord(id, "FAIL", { reason: /^A1B?_[A-Z_]+$/.test((error as Error).message) ? (error as Error).message : "NESTED_ASSERTION_OR_NATIVE_FAILURE", residueRetained: true }); throw error; }
}
function nestedFixture(profile: string) {
  // RED uses the exact existing flat generator; GREEN must supply only the
  // pinned test-owned extension, never an adopted root or caller manifest.
  const factory = (structural as any).createNestedStructuralSyntheticFixture || (structural as any).createStructuralSyntheticFixture;
  // The caller-created disposable lab is already the approved synthetic parent.
  // Avoid a redundant legacy-suite wrapper; every actual ancestor is checked.
  const token = factory(resolve(approvedParent!), profile, "A1B_SYNTHETIC_PROPOSAL_V1"); return { token, ...(structural as any).structuralFixtureFacts(token) };
}
afterAll(() => {
  safe(); if (!process.env.ROUTECAIRN_NESTED_PROOF) throw Error("NESTED_PROOF_REQUIRED");
  const text = JSON.stringify({ schemaVersion: 1, mode: "GENERATED_NESTED_SYNTHETIC_ONLY", platform: process.platform, node: process.version, templateSha256: nestedTemplate.directoryListSha256, cases: nestedCases, sentinelUnchanged: true, ownerSourceCopied: false, npm: false, privilegesChanged: false, deletionSemanticsChanged: false, materialization: "HOLD" }) + "\n";
  expect(Buffer.byteLength(text)).toBeLessThan(LIMITS.outputBytes); appendFileSync(process.env.ROUTECAIRN_NESTED_PROOF, text);
});
describe("A1B nested positive", () => {
  it.each([609, 750])("validates and disposes exact pinned topology with%i generated files", (count) => nestedObserve("NESTED_POSITIVE_" + count, () => {
    const f = nestedFixture("files" + count), plan = (structural as any).planStructuralCleanup(f.token), dirs = plan.entries.filter((e: any) => e.kind === "directory").map((e: any) => e.path).sort();
    nestedRecord("NESTED_OBSERVED_" + count, "OBSERVATION_ONLY", { actualDirectoryNames: dirs, matchesPinnedTemplate: JSON.stringify(dirs) === JSON.stringify([...nestedTemplate.directoryNames].sort()), totalEntries: plan.entries.length });
    if (!process.env.ROUTECAIRN_NESTED_ARTIFACTS) throw Error("NESTED_ARTIFACTS_REQUIRED"); writeFileSync(join(process.env.ROUTECAIRN_NESTED_ARTIFACTS, "nested-" + count + "-observed-plan.json"), JSON.stringify(plan, null, 2), { flag: "wx" });
    expect(dirs).toEqual([...nestedTemplate.directoryNames].sort()); expect(plan.files).toBe(count); expect(plan.entries).toHaveLength(count + 126); expect(plan.completeBeforeDeletion).toBe(true);
    expect(Math.max(...plan.entries.filter((e: any) => e.path !== null).map((e: any) => e.path.split("/").length))).toBe(5);
    expect(new Set(plan.entries.filter((e: any) => e.kind === "file").map((e: any) => e.parent)).size).toBe(124);
    const flat = plan.batches.flat(), positions = new Map<number, number>(flat.map((id: number, index: number) => [id, index]));
    // Linear exact-set and every-edge proof, avoiding a quadratic rescan and
    // thousands of matcher stack captures. No member or parent edge is omitted.
    expect([...flat].sort((a: number, b: number) => a - b)).toEqual(plan.entries.map((e: any) => e.id).sort((a: number, b: number) => a - b));
    expect(positions.size).toBe(plan.entries.length); expect(plan.batches.every((b: number[]) => b.length <= 512)).toBe(true);
    expect(plan.entries.every((e: any) => e.id === 0 || positions.has(e.id) && positions.has(e.parentId) && positions.get(e.id)! < positions.get(e.parentId)!)).toBe(true);
    expect(flat.slice(-2).map((id: number) => plan.entries[id].kind)).toEqual(["marker", "root"]);
    if (!process.env.ROUTECAIRN_NESTED_ARTIFACTS) throw Error("NESTED_ARTIFACTS_REQUIRED"); writeFileSync(join(process.env.ROUTECAIRN_NESTED_ARTIFACTS, "nested-" + count + "-plan.json"), JSON.stringify(plan, null, 2), { flag: "wx" });
    const operations: object[] = [], result = (structural as any).cleanupStructuralFixture(f.token, { beforeDelete: ({ removed, member, batchIndex }: any) => { operations.push({ index: removed, id: member.id, kind: member.kind, batchIndex }); } });
    expect(result.status).toBe("CONFIRMED"); expect(result.removed).toBe(count + 126); expect(operations).toHaveLength(count + 126); expect(existsSync(f.root)).toBe(false); expect(() => (structural as any).cleanupStructuralFixture(f.token)).toThrow(/CAPABILITY_STATE/);
    writeFileSync(join(process.env.ROUTECAIRN_NESTED_ARTIFACTS, "nested-" + count + "-operations.json"), JSON.stringify(operations), { flag: "wx" });
    return { ...result, directories: dirs.length, fileParents: 124, fileDepth: 5, directoryListSha256: digest(JSON.stringify(dirs)), rootAbsent: true };
  }));
});
