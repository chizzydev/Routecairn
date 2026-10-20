import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomUUID, createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { assertWorktreeMembership, parseStatus } from "../../scripts/worker-review-verifier.mjs";
const frozen = "8192cda2b8475306ecbec215f7c3623d74af25ee";
const baseline = () => ({ status: [{ status: " M", path: "src/worker.ts" }, { status: "??", path: "tests/custody.ts" }], members: ["src/worker.ts", "tests/custody.ts", "package.json"], refs: [frozen, frozen, frozen], index: [] as string[] });
describe("exact read-only review worktree membership", () => {
  it("accepts reordered exact membership", () => { const actual = baseline(); actual.members.reverse(); actual.status.reverse(); expect(() => assertWorktreeMembership(baseline(), actual)).not.toThrow(); });
  it("rejects an unexpected untracked file even when every listed source hash matches", () => { const actual = baseline(); actual.status.push({ status: "??", path: "src/unreviewed.ts" }); expect(() => assertWorktreeMembership(baseline(), actual)).toThrow("STATUS_MEMBERSHIP"); });
  it("rejects an unexpected tracked modification", () => { const actual = baseline(); actual.status.push({ status: " M", path: "package.json" }); expect(() => assertWorktreeMembership(baseline(), actual)).toThrow("STATUS_MEMBERSHIP"); });
  it("rejects a missing pending file", () => { const actual = baseline(); actual.status.pop(); expect(() => assertWorktreeMembership(baseline(), actual)).toThrow("STATUS_MEMBERSHIP"); });
  it("rejects hidden extra membership independently of status", () => { const actual = baseline(); actual.members.push("src/extra.ts"); expect(() => assertWorktreeMembership(baseline(), actual)).toThrow("FILE_MEMBERSHIP"); });
  it("rejects a changed status for an approved path", () => { const actual = baseline(); actual.status[0]!.status = "??"; expect(() => assertWorktreeMembership(baseline(), actual)).toThrow("STATUS_MEMBERSHIP"); });
  it("rejects staged changes and reference drift", () => { const actual = baseline(); actual.index.push("package.json"); expect(() => assertWorktreeMembership(baseline(), actual)).toThrow("REFERENCE_OR_INDEX"); actual.index = []; actual.refs[0] = "0".repeat(40); expect(() => assertWorktreeMembership(baseline(), actual)).toThrow("REFERENCE_OR_INDEX"); });
  it("rejects case aliases, duplicate paths and traversal", () => { for (const extra of ["src/Worker.ts", "src/worker.ts", "../outside"]) { const actual = baseline(); actual.members.push(extra); expect(() => assertWorktreeMembership(baseline(), actual)).toThrow("PATH_REFUSED"); } });
  it("parses NUL-delimited space-containing paths exactly", () => { expect(parseStatus(Buffer.from(" M src/worker.ts\0?? tests/a b.ts\0"))).toEqual([{ status: " M", path: "src/worker.ts" }, { status: "??", path: "tests/a b.ts" }]); });
  it("rejects rename, deletion, conflict, stage and truncated status records", () => { for (const value of ["R  src/a\0src/b\0", " D src/a\0", "UU src/a\0", "M  src/a\0", "?? src/a"]) expect(() => parseStatus(Buffer.from(value))).toThrow(); });
  it.skipIf(process.platform !== "win32")("rejects real unexpected and staged paths in an owned native Git fixture without creating history", () => {
    const parent = process.env.ROUTECAIRN_WORKER_LAB ?? process.env.ROUTECAIRN_TEST_RESOURCE_ROOT; if (!parent) throw Error("Owned fixture required");
    const dir = join(parent, "membership-" + randomUUID()); mkdirSync(dir);
    const nativeGit = (args: string[]) => execFileSync("C:/Program Files/Git/cmd/git.exe", ["--no-optional-locks", "-c", "core.fsmonitor=false", ...args], { cwd: dir, windowsHide: true, env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" } });
    nativeGit(["init", "--quiet", dir]); const approved = join(dir, "approved.ts"), content = "export const approved = true;\n"; writeFileSync(approved, content, { flag: "wx" });
    const observe = () => ({ status: parseStatus(nativeGit(["status", "--porcelain=v1", "-z", "--untracked-files=all"])), members: nativeGit(["ls-files", "--cached", "--others", "--exclude-standard", "-z"]).toString().split("\0").filter(Boolean), refs: [frozen, frozen, frozen], index: [] });
    const expected = observe(); expect(() => assertWorktreeMembership(expected, observe())).not.toThrow();
    writeFileSync(join(dir, "unexpected.ts"), "export const unreviewed = true;\n", { flag: "wx" });
    const unexpected = observe(); expect(() => assertWorktreeMembership(expected, unexpected)).toThrow("STATUS_MEMBERSHIP");
    nativeGit(["add", "--", "approved.ts"]); expect(() => observe()).toThrow("STATUS_REFUSED");
    expect(nativeGit(["for-each-ref", "--format=%(refname)"]).toString()).toBe("");
    writeFileSync(join(dir, "NATIVE_GIT_MEMBERSHIP_RECEIPT.json"), JSON.stringify({ expected, unexpected, listedApprovedHash: createHash("sha256").update(content).digest("hex"), unexpectedRejected: true, stagedRejected: true, noCommitsOrRefsCreated: true, retainedRoot: dir }, null, 2), { flag: "wx" });
  });

});
