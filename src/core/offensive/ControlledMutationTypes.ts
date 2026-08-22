import { z } from "zod";
import type { HttpRequest, HttpResponse } from "../http/HttpTypes.js";

export const offensiveExecutionModeSchema = z.enum(["OBSERVE", "SAFE_ACTIVE", "CONTROLLED_MUTATION", "CONTROLLED_DELETION", "LAB_DESTRUCTIVE"]);
export const mutationOutcomeSchema = z.enum(["EXPLOIT_PROVEN", "SECURE_FOR_CASE", "INCONCLUSIVE", "BLOCKED_BY_SAFETY", "ROLLBACK_VERIFIED", "CLEANUP_REQUIRED", "CLEANUP_FAILED"]);

const requestSchema = z.object({
  url: z.string().url(),
  method: z.enum(["GET", "POST", "PATCH", "PUT", "DELETE"]),
  headers: z.record(z.string()).optional(),
  body: z.string().optional(),
  skipCache: z.boolean().optional()
}).strict();

const assertionSchema = z.object({
  path: z.string().min(1),
  operator: z.enum(["EQUALS", "NOT_EQUALS", "PRESENT", "ABSENT"]),
  expectedValue: z.unknown().optional()
}).strict();

const verificationSchema = z.object({
  request: requestSchema.extend({ method: z.literal("GET") }),
  assertions: z.array(assertionSchema).min(1).optional(),
  matchPreStateHash: z.boolean().optional(),
  attempts: z.number().int().min(1).max(10).default(3),
  delayMs: z.number().int().min(0).max(30_000).default(250)
}).strict();

export const controlledMutationContractSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  caseId: z.string().regex(/^[a-zA-Z0-9._-]+$/).max(120),
  targetOrigin: z.string().url(),
  mode: offensiveExecutionModeSchema,
  environment: z.enum(["LOCAL", "TEST", "STAGING", "PRODUCTION"]),
  productionAcknowledged: z.boolean().default(false),
  authorization: z.object({
    authorizedBy: z.string().min(1),
    changeTicket: z.string().min(1),
    confirmation: z.literal("I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY"),
    authorizedAt: z.string().datetime(),
    expiresAt: z.string().datetime()
  }).strict(),
  target: z.object({
    disposable: z.literal(true),
    type: z.string().min(1),
    alias: z.string().min(1),
    identityFingerprint: z.string().regex(/^[a-f0-9]{64}$/),
    identityAssertion: assertionSchema.extend({ operator: z.literal("EQUALS"), expectedValue: z.unknown() })
  }).strict(),
  attack: z.object({
    request: requestSchema,
    allowedFields: z.array(z.string().min(1)).min(1),
    allowedValues: z.record(z.array(z.unknown()).min(1)),
    semanticEffect: z.enum(["UPDATE_EXISTING", "CREATE_DISPOSABLE", "DELETE"])
  }).strict(),
  precondition: verificationSchema.extend({ assertions: z.array(assertionSchema).min(1) }),
  impact: verificationSchema.extend({ assertions: z.array(assertionSchema).min(1) }),
  protectedAction: verificationSchema.optional(),
  rollback: z.object({ request: requestSchema, verification: verificationSchema }).strict()
}).strict();

export type OffensiveExecutionMode = z.infer<typeof offensiveExecutionModeSchema>;
export type MutationOutcome = z.infer<typeof mutationOutcomeSchema>;
export type ControlledMutationContract = z.infer<typeof controlledMutationContractSchema>;
export type MutationAssertion = z.infer<typeof assertionSchema>;
export type MutationVerification = z.infer<typeof verificationSchema>;

export interface MutationTransport { send(request: HttpRequest): Promise<HttpResponse> }

export type MutationJournalStage = "AUTHORIZED" | "PRE_STATE_CAPTURED" | "MUTATION_ARMED" | "MUTATION_SENT" | "IMPACT_VERIFIED" | "ROLLBACK_SENT" | "ROLLBACK_VERIFIED" | "CLEANUP_REQUIRED" | "CLEANUP_FAILED" | "SEALED";

export interface MutationJournalEntry {
  sequence: number;
  caseId: string;
  stage: MutationJournalStage;
  timestamp: string;
  mode: OffensiveExecutionMode;
  targetOrigin: string;
  targetIdentityFingerprint: string;
  requestMethod?: string | undefined;
  requestUrl?: string | undefined;
  requestBodyAttestation?: string | undefined;
  responseStatus?: number | undefined;
  responseHash?: string | undefined;
  outcome?: MutationOutcome | undefined;
  recoveryBundleRef?: string | undefined;
  note?: string | undefined;
}

export interface ControlledMutationResult {
  caseId: string;
  outcome: MutationOutcome;
  securityOutcome: "EXPLOIT_PROVEN" | "SECURE_FOR_CASE" | "INCONCLUSIVE" | "BLOCKED_BY_SAFETY";
  cleanupOutcome: "ROLLBACK_VERIFIED" | "CLEANUP_REQUIRED" | "CLEANUP_FAILED" | "NOT_REQUIRED";
  preStateHash?: string;
  attackResponseHash?: string;
  verificationResponseHash?: string;
  protectedActionResponseHash?: string;
  protectedActionVerified?: boolean;
  rollbackResponseHash?: string;
  journalPath: string;
  comparisonIdentity: string;
  notes: string[];
}

export interface MutationRecoveryBundle {
  caseId: string;
  targetOrigin: string;
  targetIdentityFingerprint?: string;
  authorizationExpiresAt?: string;
  contractDigest?: string;
  rollbackRequest: HttpRequest;
  rollbackVerification: MutationVerification;
  preStateHash?: string;
}
