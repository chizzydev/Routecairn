import { z } from "zod";
export const recoveryKindSchema = z.enum(["CUSTODY", "CLEANUP", "ASSURANCE", "DEPLOYMENT", "COMPARISON", "RECOVERY"]);
export const recoveryReviewSchema = z
  .object({
    kind: recoveryKindSchema,
    subjectId: z
      .string()
      .min(1)
      .max(240)
      .regex(/^[A-Za-z0-9_.:-]+$/),
    snapshotDigest: z.string().regex(/^[a-f0-9]{64}$/),
    decision: z.enum(["ACKNOWLEDGED", "ESCALATED"]),
    reason: z.enum(["OWNER_INVESTIGATION", "EVIDENCE_INCOMPLETE", "RECOVERY_PLANNING"]),
    confirmation: z.literal("I_REVIEWED_EVIDENCE_WITHOUT_RESOLVING_UNCERTAINTY")
  })
  .strict();
export const recoveryRecomputeSchema = z
  .object({
    subjectId: z.string().uuid(),
    snapshotDigest: z.string().regex(/^[a-f0-9]{64}$/),
    requestId: z.string().uuid(),
    confirmation: z.literal("I_AUTHORIZE_COMPARISON_ONLY_NO_SCAN_OR_GATE_CHANGE")
  })
  .strict();
export interface RecoveryScope {
  organizationId: string;
  actor: string;
  canReview: boolean;
  canManageWorkers: boolean;
  canRecover: boolean;
  canRecompute: boolean;
}
export interface RecoveryIssue {
  kind: z.infer<typeof recoveryKindSchema>;
  subjectId: string;
  state: string;
  title: string;
  explanation: string;
  snapshotDigest: string;
  evidence: { label: string; value: string }[];
  blockedActions: string[];
  humanReviewRequired: boolean;
  actions: { review: boolean; recompute: boolean; cleanup: boolean };
  review?: { decision: string; reason: string; createdAt: string; current: boolean };
}
export interface RecoveryCenterSnapshot {
  schemaVersion: 1;
  automaticReplay: false;
  organizationId: string;
  dispatchState: string;
  issues: RecoveryIssue[];
  inventoryWarnings: string[];
  hasMore: boolean;
  page: number;
  pageSize: number;
}

export const recoveryControlledCleanupSchema = z
  .object({
    requestId: z.string().uuid().optional(),
    subjectId: z.string().regex(/^approval:[a-f0-9-]{36}$/),
    snapshotDigest: z.string().regex(/^[a-f0-9]{64}$/),
    credentialProfileId: z.string().uuid(),
    confirmation: z.literal("I_AUTHORIZE_BOUND_CONTROLLED_CLEANUP_ONLY")
  })
  .strict();
