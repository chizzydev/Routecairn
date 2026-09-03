import { createHash } from "node:crypto";
import { controlledMutationContractSchema, type ControlledMutationContract } from "../../core/offensive/ControlledMutationTypes.js";
import type { PrivilegeMutationTestingPlan } from "../../modules/privilegeMutation/PrivilegeMutationPlanner.js";

/** Reconstruct the non-secret executable plan from the exact approved contract, never from learned traffic. */
export function approvedMutationPlan(contracts: readonly ControlledMutationContract[]): PrivilegeMutationTestingPlan {
  if (contracts.length === 0 || contracts.length > 10) throw new Error("APPROVED_MUTATION_CASE_LIMIT");
  const cases = contracts.map((input) => {
    const contract = controlledMutationContractSchema.parse(input);
    if (contract.mode !== "CONTROLLED_MUTATION" || contract.attack.semanticEffect === "DELETE" || contract.attack.allowedFields.length !== 1 || !contract.attack.request.body || !contract.rollback.request.body) throw new Error("APPROVED_PRIVILEGE_MUTATION_CONTRACT_INVALID");
    const field = contract.attack.allowedFields[0]!;
    const body = JSON.parse(contract.attack.request.body) as Record<string, unknown>;
    if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).length !== 1 || !Object.hasOwn(body, field)) throw new Error("APPROVED_PRIVILEGE_MUTATION_FIELD_MISMATCH");
    const verification = (value: ControlledMutationContract["precondition"]) => ({ request: { url: value.request.url, method: "GET" as const }, assertions: value.assertions, attempts: value.attempts, delayMs: value.delayMs, matchPreStateHash: Boolean(value.matchPreStateHash) });
    return {
      caseId: contract.caseId, category: "MASS_ASSIGNMENT" as const,
      actor: { label: "Approved disposable actor", relationship: "UNTRUSTED_ACTOR" as const, ...(contract.actor && contract.identity ? { credentialReferenceFingerprint: contract.actor.credentialReferenceFingerprint, identityFingerprint: contract.actor.identityFingerprint, identityRequest: { url: contract.identity.request.url, method: "GET" as const }, identityAssertions: contract.identity.assertions } : {}) },
      target: { type: contract.target.type, alias: contract.target.alias, identityFingerprint: contract.target.identityFingerprint, identityRequest: { url: contract.precondition.request.url, method: "GET" as const }, identityAssertions: [contract.target.identityAssertion] },
      attack: { url: contract.attack.request.url, method: contract.attack.request.method, field, valueHash: createHash("sha256").update(JSON.stringify(body[field] ?? null)).digest("hex"), allowedValueCount: contract.attack.allowedValues[field]?.length ?? 0, allowedFields: contract.attack.allowedFields, allowedValuesHash: hash(contract.attack.allowedValues), semanticEffect: contract.attack.semanticEffect },
      originalAuthority: verification(contract.precondition), impact: verification(contract.impact),
      rollback: { request: { url: contract.rollback.request.url, method: contract.rollback.request.method, bodyHash: hash(contract.rollback.request.body) }, verification: { ...verification({ ...contract.rollback.verification, assertions: contract.rollback.verification.assertions ?? [] }), matchPreStateHash: Boolean(contract.rollback.verification.matchPreStateHash) } }
    };
  });
  if (new Set(cases.map((item) => item.caseId)).size !== cases.length) throw new Error("APPROVED_MUTATION_DUPLICATE_CASE");
  return { schemaVersion: 1, enabled: true, cases, maxCases: 10, maxRequests: contracts.reduce((count, contract) => count + (contract.identity?.attempts ?? 0) + contract.precondition.attempts + 1 + contract.impact.attempts + (contract.protectedAction?.attempts ?? 0) + 1 + contract.rollback.verification.attempts, 0), notes: ["The executable plan is derived from exact approved contracts delivered in authenticated worker IPC; credentials are omitted.", "Production actor identity and disposable object identity are separate, explicit verification steps bound to execution and recovery."] };
}

function hash(value: unknown): string { return createHash("sha256").update(JSON.stringify(sort(value))).digest("hex"); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (!value || typeof value !== "object") return value; return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, sort(child)])); }
