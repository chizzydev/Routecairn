import { createHash } from "node:crypto";
import { z } from "zod";

export const observedInputPurpose = "routecairn-observed-input-v1";
export const observedInputBounds = Object.freeze({ records: 2000, urls: 8192, routes: 2000, depth: 32, nodes: 50_000, keys: 128, string: 262_144, stringBytes: 4_194_304 });
export const observedInputProducerSchema = z.enum(["BROKER_AUDIT", "BROWSER_NETWORK", "API_MAPPER"]);
export const observedInputMethodSchema = z.enum(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "UNKNOWN"]);
export const observedInputSkippedOutcomeSchema = z.enum(["duplicate-skipped", "scope-skipped", "redirect-scope-skipped", "budget-skipped", "browser-policy-blocked", "browser-network-scheduled", "browser-policy-budget-skipped"]);
const origin = z.string().min(1).max(300).refine((value) => {
  try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password && value === url.origin; }
  catch { return false; }
}, "A normalized HTTP origin is required.");
const index = z.number().int().min(0).max(observedInputBounds.records - 1);
const status = z.number().int().min(100).max(599);
const common = {
  schemaVersion: z.literal(1), targetOrigin: origin, sourceIndex: index, routeOrdinal: index,
  method: observedInputMethodSchema, originRelation: z.enum(["PRIMARY_TARGET", "OTHER_ORIGIN", "UNKNOWN"]),
  reportCompleteness: z.enum(["COMPLETED_REPORTED", "INCOMPLETE_OR_UNKNOWN"]),
  actorAttribution: z.literal("UNKNOWN"), vulnerabilityConclusion: z.literal("NOT_ASSESSED"), authorizationDecision: z.literal("UNKNOWN"),
  executable: z.literal(false), executionAuthority: z.literal("NONE"), operatorApproval: z.literal("NOT_GRANTED"), credentialsResolved: z.literal(false), cleanup: z.literal("NOT_ASSESSED")
};
const variants = [
  z.object({ ...common, producer: z.literal("BROKER_AUDIT"), disposition: z.literal("BROKER_SENT_EXACT_PAIR"), auditOutcome: z.literal("sent"), statusCode: status, responseTruncated: z.boolean().optional(), responseError: z.literal(false) }).strict(),
  z.object({ ...common, producer: z.literal("BROKER_AUDIT"), disposition: z.literal("BROKER_SENT_UNPAIRED"), auditOutcome: z.literal("sent"), auditReportedStatus: status.optional() }).strict(),
  z.object({ ...common, producer: z.literal("BROKER_AUDIT"), disposition: z.literal("BROKER_SKIPPED_OR_BLOCKED"), auditOutcome: observedInputSkippedOutcomeSchema }).strict(),
  z.object({ ...common, producer: z.literal("BROWSER_NETWORK"), disposition: z.literal("BROWSER_REPORTED_TRANSMITTED"), browserDecision: z.literal("allowed").optional(), browserTransmitted: z.literal(true) }).strict(),
  z.object({ ...common, producer: z.literal("BROWSER_NETWORK"), disposition: z.literal("BROWSER_REPORTED_BLOCKED"), browserDecision: z.literal("blocked"), browserTransmitted: z.literal(false).optional() }).strict(),
  z.object({ ...common, producer: z.literal("BROWSER_NETWORK"), disposition: z.literal("BROWSER_REPORTED_UNKNOWN"), browserDecision: z.literal("allowed").optional(), browserTransmitted: z.literal(false).optional() }).strict(),
  z.object({ ...common, producer: z.literal("API_MAPPER"), disposition: z.literal("API_DISCOVERY_CANDIDATE") }).strict()
] as const;
export const observedInputIdentitySchema = z.discriminatedUnion("disposition", variants);
export type ObservedInputIdentity = z.infer<typeof observedInputIdentitySchema>;
function canonical(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.keys(value).sort((a, b) => a < b ? -1 : a > b ? 1 : 0).map((key) => [key, value[key]]));
}
/** Flat strict allowlist only. Route ordinals and local indices intentionally depend on input order.
 * No raw path, query, response body, request ID or timestamp enters this public preimage. */
export function observedInputIdentityPreimage(input: ObservedInputIdentity): string {
  try {
    const parsed = observedInputIdentitySchema.safeParse(input);
    if (parsed.success) return JSON.stringify(canonical({ purpose: observedInputPurpose, ...parsed.data }));
  } catch { /* Hostile inputs never expose parser details. */ }
  throw new Error("INVALID_OBSERVED_INPUT_IDENTITY");
}
export function observedInputId(input: ObservedInputIdentity): string { return createHash("sha256").update(observedInputIdentityPreimage(input), "utf8").digest("hex"); }
const fingerprint = z.string().regex(/^[a-f0-9]{64}$/);
const identified = { observationId: fingerprint };
export const adaptiveObservedInputV1Schema = z.discriminatedUnion("disposition", [variants[0].extend(identified), variants[1].extend(identified), variants[2].extend(identified), variants[3].extend(identified), variants[4].extend(identified), variants[5].extend(identified), variants[6].extend(identified)]).superRefine((value, context) => {
  const { observationId, ...identity } = value;
  const parsed = observedInputIdentitySchema.safeParse(identity);
  if (!parsed.success || observationId !== observedInputId(parsed.data) || value.disposition === "BROKER_SENT_EXACT_PAIR" && value.method === "UNKNOWN") context.addIssue({ code: z.ZodIssueCode.custom, message: "Observed input identity is inconsistent." });
});
// The identity union retains precise producer-specific types; the schema independently validates them.
export type AdaptiveObservedInputV1 = ObservedInputIdentity & { observationId: string };
export const observedInputDiagnosticSchema = z.object({
  producer: observedInputProducerSchema.optional(), sourceIndex: index.optional(),
  code: z.enum(["INVALID_INPUT", "INPUT_LIMIT", "INVALID_TARGET", "INVALID_RECORD", "INVALID_URL", "INVALID_RESPONSE", "CONTRADICTORY_BROWSER", "UNKNOWN_OUTCOME"])
}).strict().refine((value) => (value.producer === undefined) === (value.sourceIndex === undefined), "Diagnostic source binding is incomplete.");
export type ObservedInputDiagnostic = z.infer<typeof observedInputDiagnosticSchema>;
