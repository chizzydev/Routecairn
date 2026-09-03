import { z } from "zod";

export const reviewStatusSchema = z.enum([
  "UNREVIEWED", "IN_REVIEW", "CONFIRMED", "FALSE_POSITIVE",
  "ACCEPTED_RISK", "DUPLICATE", "RESOLVED", "REOPENED"
]);

export const remediationStatusSchema = z.enum([
  "OPEN", "ASSIGNED", "FIX_IN_PROGRESS", "FIXED_PENDING_RETEST",
  "FIXED_VERIFIED", "WONT_FIX"
]);

export const retestStatusSchema = z.enum([
  "NOT_RETESTED", "RETEST_SCHEDULED", "RETEST_RUNNING", "RETEST_PASSED",
  "RETEST_FAILED", "RETEST_INCONCLUSIVE"
]);

export const proofReadinessSchema = z.enum([
  "NOT_READY", "MISSING_REVIEW", "MISSING_EVIDENCE", "READY", "IN_PROOF_PACK"
]);

const expectedVersion = z.number().int().positive();

export const findingReviewSchema = z.object({
  newStatus: reviewStatusSchema,
  reason: z.string().min(1).max(1_000).optional(),
  note: z.string().min(1).max(4_000).optional(),
  duplicateTargetFindingId: z.string().uuid().optional(),
  takeover: z.boolean().default(false),
  expectedVersion
}).strict();

export const findingRemediationSchema = z.object({
  newState: remediationStatusSchema,
  assigneeUserId: z.string().uuid().nullable().optional(),
  targetFixDate: z.string().date().nullable().optional(),
  note: z.string().min(1).max(4_000).optional(),
  expectedVersion
}).strict();

export const findingNoteSchema = z.object({
  text: z.string().min(1).max(4_000)
}).strict();

export const findingRetestSchema = z.object({
  scanId: z.string().uuid(),
  expectedVersion
}).strict();

export const findingVerifySchema = z.object({
  reason: z.string().min(1).max(1_000),
  ownerOverride: z.boolean().default(false),
  expectedVersion
}).strict();

export const findingSeveritySchema = z.object({
  severity: z.enum(["Critical", "High", "Medium", "Low", "Info"]),
  reason: z.string().min(1).max(1_000),
  expectedVersion
}).strict();

export const findingBulkReviewSchema = z.object({
  findingIds: z.array(z.string().uuid()).min(1).max(100),
  newStatus: z.enum(["UNREVIEWED", "IN_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK"]),
  reason: z.string().min(1).max(1_000).optional(),
  note: z.string().min(1).max(4_000).optional(),
  versions: z.record(z.string().uuid(), z.number().int().positive())
}).strict();

export const findingBulkRemediationSchema = z.object({
  findingIds: z.array(z.string().uuid()).min(1).max(100),
  newState: z.enum(["OPEN", "ASSIGNED", "FIX_IN_PROGRESS", "FIXED_PENDING_RETEST", "WONT_FIX"]),
  assigneeUserId: z.string().uuid().nullable().optional(),
  targetFixDate: z.string().date().nullable().optional(),
  note: z.string().min(1).max(4_000).optional(),
  versions: z.record(z.string().uuid(), z.number().int().positive())
}).strict();

export const findingBulkNoteSchema = z.object({
  findingIds: z.array(z.string().uuid()).min(1).max(100),
  text: z.string().min(1).max(4_000)
}).strict();

export const savedFindingViewSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1).max(120),
  query: z.object({
    scanId: z.string().uuid().optional(),
    search: z.string().max(160).optional(),
    projectId: z.string().uuid().optional(),
    targetId: z.string().uuid().optional(),
    module: z.string().max(160).optional(),
    category: z.string().max(160).optional(),
    severity: z.string().max(40).optional(),
    confidence: z.string().max(40).optional(),
    reviewStatus: reviewStatusSchema.optional(),
    remediationStatus: remediationStatusSchema.optional(),
    assigneeUserId: z.string().uuid().optional(),
    retestStatus: retestStatusSchema.optional(),
    proofReadiness: proofReadinessSchema.optional(),
    firstSeenFrom: z.string().datetime().optional(),
    firstSeenTo: z.string().datetime().optional(),
    lastSeenFrom: z.string().datetime().optional(),
    lastSeenTo: z.string().datetime().optional(),
    newOccurrence: z.boolean().optional(),
    reopened: z.boolean().optional(),
    sourceKind: z.enum(["NATIVE", "IMPORTED"]).optional(),
    evidence: z.enum(["HAS_EVIDENCE", "MISSING_EVIDENCE"]).optional(),
    sort: z.enum(["severity_desc", "confidence_desc", "first_seen_desc", "last_seen_desc", "occurrences_desc", "review", "remediation", "target", "project"]).optional(),
    page: z.number().int().positive().optional(),
    pageSize: z.number().int().positive().max(100).optional()
  }).strict(),
  columns: z.array(z.string().min(1).max(40)).max(20).default([]),
  isDefault: z.boolean().default(false),
  shared: z.boolean().default(false)
  ,expectedVersion: z.number().int().positive().optional()
}).strict();

export const savedFindingViewDeleteSchema = z.object({ id: z.string().uuid() }).strict();
export const savedFindingViewDefaultSchema = z.object({ id: z.string().uuid().nullable() }).strict();
