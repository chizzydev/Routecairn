import { createHash } from "node:crypto";
import { z } from "zod";
import type { HttpMethod } from "../../core/http/HttpTypes.js";

const methodSchema = z.enum(["POST", "PATCH", "PUT"]);
const requestSchema = z.object({ url: z.string().url(), method: methodSchema, headers: z.record(z.string()).optional(), body: z.string() }).strict();
const getRequestSchema = z.object({ url: z.string().url(), method: z.literal("GET"), headers: z.record(z.string()).optional() }).strict();
const assertionSchema = z.object({ path: z.string().min(1).regex(/^[A-Za-z0-9_.-]+$/), operator: z.enum(["EQUALS", "NOT_EQUALS", "PRESENT", "ABSENT"]), expectedValue: z.unknown().optional() }).strict();
const verificationSchema = z.object({ request: getRequestSchema, assertions: z.array(assertionSchema).min(1) }).strict();

const caseSchema = z.object({
  caseId: z.string().regex(/^[A-Za-z0-9._-]+$/).max(120),
  category: z.enum(["PRIVILEGE_ESCALATION", "MASS_ASSIGNMENT", "CROSS_TENANT_REASSIGNMENT", "OWNERSHIP_TAKEOVER", "ADMINISTRATIVE_BOUNDARY"]),
  actor: z.object({ label: z.string().min(1), relationship: z.enum(["LOWER_PRIVILEGED_ROLE", "CROSS_TENANT_MEMBER", "NON_OWNER", "UNTRUSTED_ACTOR"]) }).strict(),
  target: z.object({ type: z.string().min(1), alias: z.string().min(1), identityFingerprint: z.string().regex(/^[a-f0-9]{64}$/), identityRequest: getRequestSchema, identityAssertions: z.array(assertionSchema).min(1) }).strict(),
  attack: z.object({ request: requestSchema, field: z.string().min(1).regex(/^[A-Za-z0-9_.-]+$/), value: z.unknown(), allowedValues: z.array(z.unknown()).min(1) }).strict(),
  originalAuthority: verificationSchema,
  impact: verificationSchema,
  rollback: z.object({ request: requestSchema, verification: verificationSchema }).strict()
}).strict().superRefine((value, ctx) => {
  if (!value.attack.allowedValues.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value.attack.value))) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["attack", "value"], message: "Mutation value must be explicitly allowlisted." });
  try {
    const body = JSON.parse(value.attack.request.body) as unknown;
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("body");
    const keys = Object.keys(body as Record<string, unknown>);
    if (keys.length !== 1 || keys[0] !== value.attack.field) throw new Error("fields");
    if (JSON.stringify((body as Record<string, unknown>)[value.attack.field]) !== JSON.stringify(value.attack.value)) throw new Error("value");
  } catch {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["attack", "request", "body"], message: "Attack body must contain exactly the configured field and value." });
  }
});

export const privilegeMutationInputSchema = z.object({ schemaVersion: z.literal(1), cases: z.array(caseSchema).min(1).max(50) }).strict();
export type PrivilegeMutationInput = z.infer<typeof privilegeMutationInputSchema>;
export type PrivilegeMutationCaseInput = PrivilegeMutationInput["cases"][number];

export interface PrivilegeMutationCasePlan {
  caseId: string;
  category: PrivilegeMutationCaseInput["category"];
  actor: PrivilegeMutationCaseInput["actor"];
  target: { type: string; alias: string; identityFingerprint: string; identityRequest: { url: string; method: "GET" }; identityAssertions: PrivilegeMutationCaseInput["target"]["identityAssertions"] };
  attack: { url: string; method: HttpMethod; field: string; valueHash: string; allowedValueCount: number; allowedFields: readonly string[]; allowedValuesHash: string; semanticEffect: PrivilegeMutationCaseInput["attack"]["request"]["method"] extends never ? never : "UPDATE_EXISTING" | "CREATE_DISPOSABLE" };
  originalAuthority: { request: { url: string; method: "GET" }; assertions: PrivilegeMutationCaseInput["originalAuthority"]["assertions"]; attempts: number; delayMs: number };
  impact: { request: { url: string; method: "GET" }; assertions: PrivilegeMutationCaseInput["impact"]["assertions"]; attempts: number; delayMs: number };
  rollback: { request: { url: string; method: HttpMethod; bodyHash: string }; verification: { request: { url: string; method: "GET" }; assertions: PrivilegeMutationCaseInput["rollback"]["verification"]["assertions"]; attempts: number; delayMs: number; matchPreStateHash: boolean } };
}

export interface PrivilegeMutationTestingPlan { schemaVersion: 1; enabled: true; cases: readonly PrivilegeMutationCasePlan[]; maxCases: number; maxRequests: number; notes: readonly string[]; }

export function planPrivilegeMutationTesting(input: PrivilegeMutationInput, options: { target: string; maxCases: number }): PrivilegeMutationTestingPlan {
  if (input.cases.length > options.maxCases) throw new Error(`Privilege mutation cases exceed configured maximum of ${options.maxCases}.`);
  const targetOrigin = new URL(options.target).origin;
  const cases = input.cases.map((item) => {
    for (const request of [item.target.identityRequest, item.originalAuthority.request, item.impact.request, item.rollback.verification.request, item.attack.request, item.rollback.request]) {
      if (new URL(request.url).origin !== targetOrigin) throw new Error(`Case ${item.caseId} contains a request outside the target origin.`);
    }
    return {
      caseId: item.caseId, category: item.category, actor: item.actor,
      target: { type: item.target.type, alias: item.target.alias, identityFingerprint: item.target.identityFingerprint, identityRequest: safeGetRequest(item.target.identityRequest), identityAssertions: item.target.identityAssertions },
      attack: { url: item.attack.request.url, method: item.attack.request.method, field: item.attack.field, valueHash: hash(item.attack.value), allowedValueCount: item.attack.allowedValues.length, allowedFields: [item.attack.field], allowedValuesHash: hash(item.attack.allowedValues), semanticEffect: item.attack.request.method === "POST" ? ("CREATE_DISPOSABLE" as const) : ("UPDATE_EXISTING" as const) },
      originalAuthority: { request: safeGetRequest(item.originalAuthority.request), assertions: item.originalAuthority.assertions, attempts: verificationAttempts(item.originalAuthority), delayMs: verificationDelay(item.originalAuthority) },
      impact: { request: safeGetRequest(item.impact.request), assertions: item.impact.assertions, attempts: verificationAttempts(item.impact), delayMs: verificationDelay(item.impact) },
      rollback: { request: { url: item.rollback.request.url, method: item.rollback.request.method, bodyHash: hash(item.rollback.request.body) }, verification: { request: safeGetRequest(item.rollback.verification.request), assertions: item.rollback.verification.assertions, attempts: verificationAttempts(item.rollback.verification), delayMs: verificationDelay(item.rollback.verification), matchPreStateHash: Boolean((item.rollback.verification as { matchPreStateHash?: boolean }).matchPreStateHash) } }
    };
  });
  const requestBudget = input.cases.reduce((total, item) => total + verificationAttempts(item.originalAuthority) + 1 + verificationAttempts(item.impact) + 1 + verificationAttempts(item.rollback.verification), 0);
  return { schemaVersion: 1, enabled: true, cases, maxCases: options.maxCases, maxRequests: requestBudget, notes: ["Only operator-supplied cases are executed.", "Exactly one explicitly allowlisted authority field/value is transmitted per case.", "Exactly enough request budget is reserved for configured verification attempts and cleanup."] };
}

function verificationAttempts(value: unknown): number { const attempts = (value as { attempts?: unknown }).attempts; return typeof attempts === "number" && Number.isInteger(attempts) && attempts > 0 ? attempts : 3; }
function verificationDelay(value: unknown): number { const delay = (value as { delayMs?: unknown }).delayMs; return typeof delay === "number" && Number.isInteger(delay) && delay >= 0 ? delay : 250; }

function safeGetRequest(request: { url: string; method: "GET"; headers?: Record<string, string> | undefined }): { url: string; method: "GET" } { return { url: request.url, method: "GET" }; }
function hash(value: unknown): string { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
