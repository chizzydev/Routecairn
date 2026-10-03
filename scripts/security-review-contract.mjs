import { createHash, createPublicKey, verify } from "node:crypto";
import { z } from "zod";

export const requiredReviewScope = ["request-safety", "authorization", "active-testing", "browser", "plugins", "secrets-evidence", "oast", "control-plane", "supply-chain"];
const date = z.string().datetime({ offset: true });
const keyId = z.string().regex(/^[A-Za-z0-9._-]{3,80}$/u);
export const reviewerRegistrySchema = z.object({
  schemaVersion: z.literal(1),
  reviewers: z.array(z.object({
    keyId, organization: z.string().min(2).max(160), independence: z.literal("INDEPENDENT_THIRD_PARTY"),
    active: z.boolean(), publicKeyPem: z.string().min(80).max(4096)
  }).strict())
}).strict().superRefine((value, context) => {
  if (new Set(value.reviewers.map((entry) => entry.keyId)).size !== value.reviewers.length) context.addIssue({ code: "custom", message: "Duplicate reviewer key identities." });
  const keys = value.reviewers.map((entry) => entry.publicKeyPem.trim());
  if (new Set(keys).size !== keys.length) context.addIssue({ code: "custom", message: "Duplicate reviewer keys." });
});
export const reviewSchema = z.object({
  schemaVersion: z.literal(2), release: z.string().regex(/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u),
  sourceCommit: z.string().regex(/^[a-f0-9]{40}$/u), reviewerKeyId: keyId,
  reviewerOrganization: z.string().min(2).max(160), independence: z.literal("INDEPENDENT_THIRD_PARTY"),
  startedAt: date, completedAt: date, expiresAt: date,
  scope: z.array(z.enum(requiredReviewScope)).length(requiredReviewScope.length), disposition: z.literal("ACCEPTED"),
  unresolved: z.object({ critical: z.literal(0), high: z.literal(0), medium: z.number().int().nonnegative(), low: z.number().int().nonnegative() }).strict(),
  reportPath: z.string().regex(/^security-reviews\/v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\.report\.(?:md|pdf|json)$/u),
  reportSha256: z.string().regex(/^[a-f0-9]{64}$/u), signature: z.string().regex(/^[A-Za-z0-9+/]{86}==$/u)
}).strict().superRefine((value, context) => {
  if (new Set(value.scope).size !== requiredReviewScope.length) context.addIssue({ code: "custom", message: "Incomplete review scope." });
  if (!value.reportPath.startsWith(`security-reviews/${value.release}.report.`)) context.addIssue({ code: "custom", message: "Report release mismatch." });
});
export function canonicalReviewPayload(value) {
  const { signature: _signature, ...payload } = value;
  return JSON.stringify(sortObject(payload));
}
function sortObject(value) {
  if (Array.isArray(value)) return value.map(sortObject);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortObject(value[key])]));
  return value;
}
export function verifyReview({ attestation, registry, release, reportBytes, now = Date.now() }) {
  const review = reviewSchema.parse(attestation);
  const trusted = reviewerRegistrySchema.parse(registry);
  if (review.release !== release) throw new Error("Review release mismatch.");
  const reviewer = trusted.reviewers.find((entry) => entry.keyId === review.reviewerKeyId && entry.active);
  if (!reviewer || reviewer.organization !== review.reviewerOrganization) throw new Error("Independent reviewer is not trusted and active.");
  const start = Date.parse(review.startedAt), completed = Date.parse(review.completedAt), expiry = Date.parse(review.expiresAt);
  if (start > completed || completed > now || completed >= expiry || expiry <= now) throw new Error("Review validity window is invalid or expired.");
  if (createHash("sha256").update(reportBytes).digest("hex") !== review.reportSha256) throw new Error("Review report digest mismatch.");
  const key = createPublicKey(reviewer.publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Review key must be Ed25519.");
  const signature = Buffer.from(review.signature, "base64");
  if (signature.length !== 64 || signature.toString("base64") !== review.signature || !verify(null, Buffer.from(canonicalReviewPayload(review)), key, signature)) throw new Error("Security review signature is invalid.");
  return review;
}
