import { createHash } from "node:crypto";
import { z } from "zod";
import { observedInputMethodSchema, observedInputProducerSchema } from "./AdaptiveObservedInputIR.js";

export const discoveryCandidatePurpose = "routecairn-discovery-candidate-v1";
export const discoveryCandidateBounds = Object.freeze({ groups: 2000, references: 64, totalReferences: 2000, diagnostics: 2000 });
export const discoveryDispositionSchema = z.enum(["BROKER_SENT_EXACT_PAIR", "BROKER_SENT_UNPAIRED", "BROKER_SKIPPED_OR_BLOCKED", "BROWSER_REPORTED_TRANSMITTED", "BROWSER_REPORTED_BLOCKED", "BROWSER_REPORTED_UNKNOWN", "API_DISCOVERY_CANDIDATE"]);
const fingerprint = z.string().regex(/^[a-f0-9]{64}$/);
const index = z.number().int().min(0).max(1999);
const origin = z.string().min(1).max(300).refine((value) => { try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) && value === url.origin && !url.username && !url.password; } catch { return false; } }, "Normalized origin required.");
const relation = z.enum(["PRIMARY_TARGET", "OTHER_ORIGIN", "UNKNOWN"]);
const identitySchema = z.object({ targetOrigin: origin, originRelation: relation, routeOrdinal: index, method: observedInputMethodSchema }).strict();
export type DiscoveryCandidateIdentity = z.infer<typeof identitySchema>;
export function discoveryBinaryCompare(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
function canonical(value: unknown): unknown { return Array.isArray(value) ? value.map(canonical) : value && typeof value === "object" ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => discoveryBinaryCompare(a, b)).map(([key, item]) => [key, canonical(item)])) : value; }
/** Ordinals are report-local, order-sensitive metadata, never a portable route or a URL binding. */
export function discoveryCandidateIdentityPreimage(input: DiscoveryCandidateIdentity): string {
  try { if (safeData(input)) { const parsed = identitySchema.safeParse(input); if (parsed.success) return JSON.stringify(canonical({ purpose: discoveryCandidatePurpose, ...parsed.data })); } } catch { /* Fixed error only. */ }
  throw new Error("INVALID_DISCOVERY_CANDIDATE_IDENTITY");
}
export function discoveryCandidateId(input: DiscoveryCandidateIdentity): string { return createHash("sha256").update(discoveryCandidateIdentityPreimage(input), "utf8").digest("hex"); }
export const discoverySourceReferenceSchema = z.object({ producer: observedInputProducerSchema, sourceIndex: index, observationId: fingerprint, disposition: discoveryDispositionSchema }).strict().refine((value) => value.producer === "BROKER_AUDIT" ? value.disposition.startsWith("BROKER_") : value.producer === "BROWSER_NETWORK" ? value.disposition.startsWith("BROWSER_") : value.disposition === "API_DISCOVERY_CANDIDATE", "Producer grade mismatch.");
export type DiscoverySourceReference = z.infer<typeof discoverySourceReferenceSchema>;
const count = z.number().int().min(0).max(discoveryCandidateBounds.references);
export const discoveryEvidenceSummarySchema = z.object({ BROKER_SENT_EXACT_PAIR: count, BROKER_SENT_UNPAIRED: count, BROKER_SKIPPED_OR_BLOCKED: count, BROWSER_REPORTED_TRANSMITTED: count, BROWSER_REPORTED_BLOCKED: count, BROWSER_REPORTED_UNKNOWN: count, API_DISCOVERY_CANDIDATE: count }).strict();
export type DiscoveryEvidenceSummary = z.infer<typeof discoveryEvidenceSummarySchema>;
const readiness = z.enum(["BLOCKED_OR_CONTRADICTORY", "UNKNOWN_OR_CROSS_ORIGIN", "SENT_BUT_RESPONSE_UNCONFIRMED", "BROWSER_OBSERVATION_UNCONFIRMED", "BROWSER_TRANSMISSION_REPORTED_ONLY", "DISCOVERED_NOT_CONFIRMED_TRANSMITTED", "EXACT_EXCHANGE_ALREADY_OBSERVED"]);
const nextStep = z.enum(["REVIEW_EXISTING_EVIDENCE", "REVIEW_FOR_POTENTIAL_PROBE", "RESOLVE_CONTRADICTION", "NO_PROBE_PROPOSAL"]);
const requirement = z.enum(["CHECK_SCOPE", "VERIFY_AUTHORIZED_TARGET", "VERIFY_NON_MUTATING_EFFECT", "VERIFY_METHOD_AND_ROUTE_BINDING", "VERIFY_CREDENTIAL_CONTEXT", "CONFIRM_OUTCOME", "REVIEW_BLOCK", "REVIEW_EVIDENCE_CORRELATION", "RESOLVE_UPSTREAM_DIAGNOSTICS", "CONFIRM_REPORT_COMPLETENESS"]);
const rationale = z.enum(["REPORT_LOCAL_ORDINAL", "REVIEW_ONLY", "EXCHANGE_CORRELATED", "SENT_UNCONFIRMED", "BLOCK_REPORTED", "BROWSER_TRANSMISSION_METADATA", "BROWSER_BLOCK_METADATA", "BROWSER_UNKNOWN_METADATA", "DISCOVERY_ONLY", "MIXED_EVIDENCE", "UPSTREAM_DIAGNOSTICS_PRESENT", "UNKNOWN_METHOD_OR_OTHER_ORIGIN", "INCOMPLETE_REPORT"]);
const completeness = z.enum(["COMPLETED_REPORTED", "INCOMPLETE_OR_UNKNOWN"]);
const ranks: Record<z.infer<typeof readiness>, number> = { BLOCKED_OR_CONTRADICTORY: 0, UNKNOWN_OR_CROSS_ORIGIN: 1, SENT_BUT_RESPONSE_UNCONFIRMED: 2, BROWSER_OBSERVATION_UNCONFIRMED: 3, BROWSER_TRANSMISSION_REPORTED_ONLY: 4, DISCOVERED_NOT_CONFIRMED_TRANSMITTED: 5, EXACT_EXCHANGE_ALREADY_OBSERVED: 6 };
/** Transparent review heuristic only. Counts never confer probe permission or vulnerability likelihood. */
export function discoveryReviewFacts(summary: DiscoveryEvidenceSummary, method: DiscoveryCandidateIdentity["method"], originRelation: DiscoveryCandidateIdentity["originRelation"], upstreamEvidenceIncomplete: boolean, reportCompleteness: z.infer<typeof completeness>) {
  const blocked = summary.BROKER_SKIPPED_OR_BLOCKED + summary.BROWSER_REPORTED_BLOCKED > 0;
  const uncertain = summary.BROKER_SENT_UNPAIRED > 0;
  const unknown = originRelation !== "PRIMARY_TARGET" || method === "UNKNOWN";
  const grade: z.infer<typeof readiness> = blocked || upstreamEvidenceIncomplete ? "BLOCKED_OR_CONTRADICTORY" : unknown ? "UNKNOWN_OR_CROSS_ORIGIN" : uncertain ? "SENT_BUT_RESPONSE_UNCONFIRMED" : summary.BROWSER_REPORTED_UNKNOWN > 0 ? "BROWSER_OBSERVATION_UNCONFIRMED" : summary.BROKER_SENT_EXACT_PAIR > 0 ? "EXACT_EXCHANGE_ALREADY_OBSERVED" : summary.BROWSER_REPORTED_TRANSMITTED > 0 ? "BROWSER_TRANSMISSION_REPORTED_ONLY" : "DISCOVERED_NOT_CONFIRMED_TRANSMITTED";
  const step: z.infer<typeof nextStep> = blocked || upstreamEvidenceIncomplete ? "RESOLVE_CONTRADICTION" : unknown ? "NO_PROBE_PROPOSAL" : grade === "DISCOVERED_NOT_CONFIRMED_TRANSMITTED" ? "REVIEW_FOR_POTENTIAL_PROBE" : "REVIEW_EXISTING_EVIDENCE";
  const requirements: z.infer<typeof requirement>[] = ["CHECK_SCOPE", "VERIFY_AUTHORIZED_TARGET", "VERIFY_NON_MUTATING_EFFECT", "VERIFY_METHOD_AND_ROUTE_BINDING", "VERIFY_CREDENTIAL_CONTEXT"];
  if (uncertain || summary.BROWSER_REPORTED_UNKNOWN || summary.BROWSER_REPORTED_TRANSMITTED || summary.API_DISCOVERY_CANDIDATE) requirements.push("CONFIRM_OUTCOME");
  if (summary.BROKER_SENT_EXACT_PAIR || uncertain || summary.BROWSER_REPORTED_TRANSMITTED) requirements.push("REVIEW_EVIDENCE_CORRELATION");
  if (blocked || upstreamEvidenceIncomplete) requirements.push("REVIEW_BLOCK");
  if (upstreamEvidenceIncomplete) requirements.push("RESOLVE_UPSTREAM_DIAGNOSTICS");
  if (reportCompleteness === "INCOMPLETE_OR_UNKNOWN") requirements.push("CONFIRM_REPORT_COMPLETENESS");
  const reasons: z.infer<typeof rationale>[] = ["REPORT_LOCAL_ORDINAL", "REVIEW_ONLY"];
  const labels = ["EXCHANGE_CORRELATED", "SENT_UNCONFIRMED", "BLOCK_REPORTED", "BROWSER_TRANSMISSION_METADATA", "BROWSER_BLOCK_METADATA", "BROWSER_UNKNOWN_METADATA", "DISCOVERY_ONLY"] as const;
  discoveryDispositionSchema.options.forEach((key, position) => { if (summary[key]) reasons.push(labels[position]!); });
  const mixedEvidence = Object.values(summary).filter((value) => value > 0).length > 1;
  if (mixedEvidence) reasons.push("MIXED_EVIDENCE"); if (unknown) reasons.push("UNKNOWN_METHOD_OR_OTHER_ORIGIN");
  if (upstreamEvidenceIncomplete) reasons.push("UPSTREAM_DIAGNOSTICS_PRESENT"); if (reportCompleteness === "INCOMPLETE_OR_UNKNOWN") reasons.push("INCOMPLETE_REPORT");
  return { readiness: grade, nextStep: step, triageRank: ranks[grade], mixedEvidence, alreadyObservedExchange: summary.BROKER_SENT_EXACT_PAIR > 0, requirements: requirements.sort(discoveryBinaryCompare), rationale: reasons.sort(discoveryBinaryCompare) };
}
const shape = z.object({ schemaVersion: z.literal(1), candidateId: fingerprint, ...identitySchema.shape,
  sourceReferences: z.array(discoverySourceReferenceSchema).min(1).max(discoveryCandidateBounds.references), evidenceSummary: discoveryEvidenceSummarySchema,
  readiness, nextStep, triageRank: z.number().int().min(0).max(6), producerCoverage: z.number().int().min(1).max(3), mixedEvidence: z.boolean(), alreadyObservedExchange: z.boolean(), upstreamEvidenceIncomplete: z.boolean(), reportCompleteness: completeness,
  requirements: z.array(requirement).min(5).max(10), rationale: z.array(rationale).min(2).max(13),
  status: z.literal("REQUIRES_OPERATOR_REVIEW"), executable: z.literal(false), executionAuthority: z.literal("NONE"), approval: z.literal("NOT_GRANTED"), credentialsResolved: z.literal(false), authorizationDecision: z.literal("UNKNOWN"), vulnerabilityConclusion: z.literal("NOT_ASSESSED"), cleanup: z.literal("NOT_ASSESSED")
}).strict();
export type DiscoveryCandidateV1 = z.infer<typeof shape>;
const producerOrder = { BROKER_AUDIT: 0, BROWSER_NETWORK: 1, API_MAPPER: 2 };
export const discoveryCandidateV1Schema = shape.superRefine((value, context) => {
  const invalid = () => context.addIssue({ code: z.ZodIssueCode.custom, message: "Discovery candidate metadata is inconsistent." });
  const parsedIdentity = identitySchema.safeParse({ targetOrigin: value.targetOrigin, method: value.method, routeOrdinal: value.routeOrdinal, originRelation: value.originRelation });
  if (!parsedIdentity.success || value.candidateId !== discoveryCandidateId(parsedIdentity.data)) { invalid(); return; }
  const summary = emptyDiscoveryEvidenceSummary(); const ids = new Set<string>(); const slots = new Set<string>(); const producers = new Set<string>();
  value.sourceReferences.forEach((reference, position) => {
    const previous = value.sourceReferences[position - 1]; const slot = `${reference.producer}:${reference.sourceIndex}`;
    if (ids.has(reference.observationId) || slots.has(slot) || previous && (producerOrder[previous.producer] > producerOrder[reference.producer] || previous.producer === reference.producer && previous.sourceIndex >= reference.sourceIndex)) invalid();
    ids.add(reference.observationId); slots.add(slot); producers.add(reference.producer); summary[reference.disposition]++;
  });
  if (value.producerCoverage !== producers.size || discoveryDispositionSchema.options.some((key) => value.evidenceSummary[key] !== summary[key])) invalid();
  const facts = discoveryReviewFacts(summary, value.method, value.originRelation, value.upstreamEvidenceIncomplete, value.reportCompleteness);
  for (const key of ["readiness", "nextStep", "triageRank", "mixedEvidence", "alreadyObservedExchange"] as const) if (value[key] !== facts[key]) invalid();
  if (JSON.stringify(value.requirements) !== JSON.stringify(facts.requirements) || JSON.stringify(value.rationale) !== JSON.stringify(facts.rationale)) invalid();
});
export function emptyDiscoveryEvidenceSummary(): DiscoveryEvidenceSummary { return { BROKER_SENT_EXACT_PAIR: 0, BROKER_SENT_UNPAIRED: 0, BROKER_SKIPPED_OR_BLOCKED: 0, BROWSER_REPORTED_TRANSMITTED: 0, BROWSER_REPORTED_BLOCKED: 0, BROWSER_REPORTED_UNKNOWN: 0, API_DISCOVERY_CANDIDATE: 0 }; }
/** Bounded independent boundary for caller-supplied public data, without getters or serialization. */
function safeData(input: unknown): boolean {
  let nodes = 0; let characters = 0; const ancestors = new Set<object>();
  const walk = (value: unknown, depth: number): boolean => {
    if (++nodes > 1200 || depth > 6) return false;
    if (typeof value === "string") { characters += value.length; return value.length <= 300 && characters <= 40_000; }
    if (value === null || typeof value === "boolean") return true;
    if (typeof value === "number") return Number.isFinite(value);
    if (!value || typeof value !== "object" || ancestors.has(value) || !Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype) return false;
    if (Array.isArray(value) && value.length > discoveryCandidateBounds.references) return false;
    const keys = Reflect.ownKeys(value); if (keys.length > 65) return false; ancestors.add(value);
    for (const key of keys) { if (typeof key !== "string" || key.length > 80) return false; const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor || !("value" in descriptor) || !walk(descriptor.value, depth + 1)) return false; }
    ancestors.delete(value); return true;
  };
  try { return walk(input, 0); } catch { return false; }
}
export function parseAdaptiveDiscoveryCandidate(input: unknown): DiscoveryCandidateV1 | undefined { try { if (safeData(input)) { const parsed = discoveryCandidateV1Schema.safeParse(input); if (parsed.success) return parsed.data; } } catch { /* No private parser details returned. */ } }
/** Review ordering: conservative disposition, distinct producer coverage descending, binary ID tie. */
export function compareDiscoveryCandidates(a: DiscoveryCandidateV1, b: DiscoveryCandidateV1): number { return a.triageRank - b.triageRank || b.producerCoverage - a.producerCoverage || discoveryBinaryCompare(a.candidateId, b.candidateId); }
const omittedCode = z.enum(["SOURCE_REFERENCE_LIMIT", "CANDIDATE_LIMIT", "INVALID_CANDIDATE", "INVALID_OBSERVATION"]);
export const discoveryPlannerDiagnosticSchema = z.object({ code: z.enum(["SOURCE_REFERENCE_LIMIT", "CANDIDATE_LIMIT", "INVALID_CANDIDATE", "INVALID_OBSERVATION", "UPSTREAM_FAILED", "INVALID_INPUT"]), observationIndex: index.optional(), producer: observedInputProducerSchema.optional(), sourceIndex: index.optional(), observationId: fingerprint.optional() }).strict().refine((value) => [value.observationIndex, value.producer, value.sourceIndex, value.observationId].every((item) => item === undefined) || [value.observationIndex, value.producer, value.sourceIndex, value.observationId].every((item) => item !== undefined), "Diagnostic binding incomplete.");
export type DiscoveryPlannerDiagnostic = z.infer<typeof discoveryPlannerDiagnosticSchema>;
const ledgerFields = { observationIndex: index, producer: observedInputProducerSchema, sourceIndex: index, observationId: fingerprint };
export const discoveryAccountingEntrySchema = z.discriminatedUnion("state", [z.object({ ...ledgerFields, state: z.literal("CANDIDATE"), candidateId: fingerprint }).strict(), z.object({ ...ledgerFields, state: z.literal("OMITTED"), code: omittedCode }).strict()]);
export type DiscoveryAccountingEntry = z.infer<typeof discoveryAccountingEntrySchema>;
