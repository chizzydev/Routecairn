import { createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";

const releaseIndex = process.argv.indexOf("--release");
const release = (releaseIndex >= 0 ? process.argv[releaseIndex + 1] : undefined) || process.env.GITHUB_REF_NAME;
if (!release?.match(/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u)) throw new Error("Pass --release vX.Y.Z.");
const packageJson = JSON.parse(await readFile("package.json", "utf8"));
if (release !== `v${packageJson.version}`) throw new Error("Security review release does not match package version.");
const attestation = JSON.parse(await readFile(`security-reviews/${release}.review.json`, "utf8"));
const registry = JSON.parse(await readFile("security-reviews/trusted-reviewers.json", "utf8"));
const reviewer = registry.reviewers.find((entry) => entry.keyId === attestation.reviewerKeyId && entry.active === true);
if (!reviewer) throw new Error("Security review is not signed by an active trusted reviewer.");
const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const requiredScope = ["request-safety", "authorization", "active-testing", "browser", "plugins", "secrets-evidence", "oast", "control-plane", "supply-chain"];
if (attestation.schemaVersion !== 1 || attestation.release !== release || attestation.sourceCommit !== commit) throw new Error("Review identity does not match this release commit.");
if (attestation.independence !== "INDEPENDENT_THIRD_PARTY" || reviewer.independence !== "INDEPENDENT_THIRD_PARTY" || attestation.reviewerOrganization !== reviewer.organization || attestation.disposition !== "ACCEPTED") throw new Error("Independent review has not accepted the release.");
if (attestation.unresolved?.critical !== 0 || attestation.unresolved?.high !== 0) throw new Error("Review has unresolved critical or high findings.");
if (Date.parse(attestation.expiresAt) <= Date.now() || Date.parse(attestation.startedAt) > Date.parse(attestation.completedAt) || Date.parse(attestation.completedAt) > Date.parse(attestation.expiresAt)) throw new Error("Review is expired or has an invalid validity window.");
if (!requiredScope.every((item) => attestation.scope?.includes(item))) throw new Error("Review scope is incomplete.");
if (!/^[a-f0-9]{64}$/u.test(attestation.reportSha256) || typeof attestation.signature !== "string") throw new Error("Review report digest or signature is invalid.");
const { signature, ...payload } = attestation;
const canonical = JSON.stringify(sortObject(payload));
if (!verify(null, Buffer.from(canonical), createPublicKey(reviewer.publicKeyPem), Buffer.from(signature, "base64"))) throw new Error("Security review signature is invalid.");
process.stdout.write(`Independent security review verified for ${release}.\n`);

function sortObject(value) {
  if (Array.isArray(value)) return value.map(sortObject);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortObject(value[key])]));
  return value;
}
