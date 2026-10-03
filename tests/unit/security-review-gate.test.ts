import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
// Release policy is executable tooling, tested with disposable keys and Git repositories.
// @ts-expect-error JavaScript tooling does not ship declarations.
import { canonicalReviewPayload, requiredReviewScope, verifyReview } from "../../scripts/security-review-contract.mjs";
// @ts-expect-error JavaScript tooling does not ship declarations.
import { verifyReviewedSource } from "../../scripts/security-review-source.mjs";

const reportBytes = Buffer.from("Independent assessment fixture; not a release attestation.");
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const registry = { schemaVersion: 1, reviewers: [{ keyId: "test-outside", organization: "Test independent assessor", independence: "INDEPENDENT_THIRD_PARTY", active: true, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }) }] };
const now = Date.parse("2026-10-03T12:00:00Z");
function fixture(patch = {}) {
  const review = { schemaVersion: 2, release: "v0.1.0", sourceCommit: "a".repeat(40), reviewerKeyId: "test-outside", reviewerOrganization: "Test independent assessor", independence: "INDEPENDENT_THIRD_PARTY", startedAt: "2026-10-01T12:00:00Z", completedAt: "2026-10-02T12:00:00Z", expiresAt: "2026-10-04T12:00:00Z", scope: requiredReviewScope, disposition: "ACCEPTED", unresolved: { critical: 0, high: 0, medium: 0, low: 0 }, reportPath: "security-reviews/v0.1.0.report.md", reportSha256: createHash("sha256").update(reportBytes).digest("hex"), signature: "", ...patch };
  review.signature = sign(null, Buffer.from(canonicalReviewPayload(review)), privateKey).toString("base64");
  return review;
}
const check = (attestation: unknown, trusted = registry, bytes = reportBytes) => verifyReview({ attestation, registry: trusted, release: "v0.1.0", reportBytes: bytes, now });
describe("independent release attestation policy", () => {
  it("does not interpret branch or PR refs as release tags", () => {
    const run = (environment: NodeJS.ProcessEnv, args: string[] = []) => execFileSync(process.execPath, ["scripts/verify-release-policy.mjs", ...args], { encoding: "utf8", env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"] });
    expect(run({ GITHUB_REF_TYPE: "branch", GITHUB_REF_NAME: "14/merge" })).toContain("verified");
    expect(() => run({ GITHUB_REF_TYPE: "tag", GITHUB_REF_NAME: "v0.2.0" })).toThrow();
    expect(() => run({}, ["--tag"])).toThrow();
  });
  it("accepts a complete authenticated report", () => expect(check(fixture()).release).toBe("v0.1.0"));
  it.each([
    { startedAt: "invalid" }, { completedAt: "2026-10-05T12:00:00Z" }, { expiresAt: "2026-10-03T12:00:00Z" },
    { startedAt: "2026-10-03T12:00:00Z" }, { scope: Array(9).fill("request-safety") }, { independence: "SELF_MAINTAINED" },
    { unresolved: { critical: 0, high: 1, medium: 0, low: 0 } }, { reportPath: "../report.md" }, { reportPath: "security-reviews/v0.2.0.report.md" },
    { injected: true }, { sourceCommit: "HEAD" }, { reportSha256: "bad" }, { release: "v0.2.0" }
  ])("rejects invalid or incomplete signed claims %j", patch => expect(() => check(fixture(patch))).toThrow());
  it("rejects a modified report", () => expect(() => check(fixture(), registry, Buffer.from("modified"))).toThrow(/digest/));
  it("rejects signature tampering", () => { const review = fixture(); review.signature = Buffer.alloc(64).toString("base64"); expect(() => check(review)).toThrow(/signature/); });
  it("rejects revoked and unknown reviewers", () => { expect(() => check(fixture(), { ...registry, reviewers: [] })).toThrow(); expect(() => check(fixture(), { ...registry, reviewers: [{ ...registry.reviewers[0]!, active: false }] })).toThrow(); });
  it("rejects duplicate reviewer identities", () => expect(() => check(fixture(), { ...registry, reviewers: [...registry.reviewers, ...registry.reviewers] })).toThrow(/Duplicate/));
  it("rejects a different organization", () => expect(() => check(fixture({ reviewerOrganization: "Implementation team" }))).toThrow());
  it("binds post-review commits to evidence files only", () => {
    const cwd = mkdtempSync(join(tmpdir(), "routecairn-review-git-"));
    const git = (...args: string[]) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    try {
      git("init"); git("config", "user.name", "Review fixture"); git("config", "user.email", "fixture@example.test"); git("config", "commit.gpgsign", "false");
      writeFileSync(join(cwd, "source.ts"), "reviewed\n"); git("add", "."); git("commit", "-m", "source");
      const sourceCommit = git("rev-parse", "HEAD"); mkdirSync(join(cwd, "security-reviews"));
      writeFileSync(join(cwd, "security-reviews/v0.1.0.review.json"), "fixture"); writeFileSync(join(cwd, "security-reviews/v0.1.0.report.md"), reportBytes);
      git("add", "."); git("commit", "-m", "review evidence"); const review = fixture({ sourceCommit });
      expect(() => verifyReviewedSource(review, { cwd })).not.toThrow();
      writeFileSync(join(cwd, "source.ts"), "unreviewed\n"); expect(() => verifyReviewedSource(review, { cwd })).toThrow(/clean/);
      git("add", "."); git("commit", "-m", "unreviewed change"); expect(() => verifyReviewedSource(review, { cwd })).toThrow(/source changes/);
    } finally { rmSync(cwd, { recursive: true, force: true }); }
  });
});
