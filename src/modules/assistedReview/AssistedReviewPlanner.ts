import { readFile } from "node:fs/promises";
import { z } from "zod";
import { AppError } from "../../core/errors/AppError.js";
import { assistedReviewLanes, type AssistedReviewPlan } from "./AssistedReviewTypes.js";
import { assistedFindingModules } from "../../core/findings/AssistedWorkflowFindingAcceptance.js";

export const assistedReviewInputSchema = z.object({
  schemaVersion: z.literal(1),
  reviewId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,119}$/),
  title: z.string().min(3).max(160),
  focus: z.array(z.enum(assistedReviewLanes)).min(1).max(assistedReviewLanes.length),
  requiredLanes: z.array(z.enum(assistedReviewLanes)).min(1).max(assistedReviewLanes.length),
  cases: z.array(z.object({ workflowId: z.string().regex(/^[a-z][a-z0-9-]{1,99}$/), caseId: z.string().regex(/^[a-zA-Z0-9_.:/-]{1,240}$/), lane: z.enum(assistedReviewLanes) }).strict()).min(1).max(500),
  authentication: z.object({ requireVerifiedIdentity: z.boolean().default(true), requireAccountPair: z.boolean().default(false) }).strict().default({}),
  completionGate: z.object({
    requireNoBlocked: z.boolean().default(true),
    requireNoInconclusive: z.boolean().default(true),
    requireHumanReviewForFindings: z.literal(true)
  }).strict(),
  customer: z.object({ name: z.string().min(1).max(160) }).strict().optional()
}).strict();

export async function loadAssistedReviewInput(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

export function planAssistedReview(input: unknown): AssistedReviewPlan {
  const value = assistedReviewInputSchema.parse(input);
  const focus = [...new Set(value.focus)];
  const requiredLanes = [...new Set(value.requiredLanes)];
  if (requiredLanes.some((lane) => !focus.includes(lane))) throw new AppError("Every required assisted-review lane must be selected in focus.", "ASSISTED_REVIEW_REQUIRED_LANE_NOT_SELECTED");
  if (value.cases.some((item) => !focus.includes(item.lane))) throw new AppError("Every review case must belong to a selected lane.", "ASSISTED_REVIEW_CASE_LANE_INVALID");
  for (const item of value.cases) {
    if (!assistedFindingModules.has(item.workflowId) && item.workflowId !== "browser-crawler") throw new AppError("Unknown assisted workflow module.", "ASSISTED_REVIEW_WORKFLOW_INVALID");
    const lanes = item.workflowId === "secret-boundary" ? ["API", "BROWSER"] : item.workflowId === "browser-crawler" ? ["BROWSER"] : item.workflowId === "authentication-lifecycle" ? ["AUTH_LIFECYCLE"] : item.workflowId === "billing-entitlement-security" ? ["PAYMENT_ENTITLEMENT"] : ["api-graphql-authorization", "operational-endpoint-security"].includes(item.workflowId) ? ["API"] : ["AUTHORIZATION"];
    if (!lanes.includes(item.lane)) throw new AppError("The workflow does not support the selected review lane.", "ASSISTED_REVIEW_WORKFLOW_LANE_INVALID");
  }
  if (new Set(value.cases.map((item) => `${item.workflowId}/${item.caseId}`)).size !== value.cases.length) throw new AppError("Duplicate workflow/case references are not permitted.", "ASSISTED_REVIEW_DUPLICATE_CASE");
  if (requiredLanes.some((lane) => !value.cases.some((item) => item.lane === lane))) throw new AppError("Every required lane needs an explicit case inventory.", "ASSISTED_REVIEW_CASE_INVENTORY_REQUIRED");
  return {
    schemaVersion: 1,
    reviewId: value.reviewId,
    title: value.title,
    focus,
    requiredLanes,
    cases: value.cases,
    requireVerifiedIdentity: value.authentication.requireVerifiedIdentity,
    requireAccountPair: value.authentication.requireAccountPair,
    requireNoBlocked: value.completionGate.requireNoBlocked,
    requireNoInconclusive: value.completionGate.requireNoInconclusive,
    requireHumanReviewForFindings: true,
    ...(value.customer ? { customerName: value.customer.name } : {}),
    notes: [
      "Scanner conclusions remain queued for human confirmation before proof-pack or customer-report acceptance.",
      "PROVEN, INCONCLUSIVE, NOT_ASSESSED, and BLOCKED are preserved as separate assessment outcomes.",
      "Cleanup failure is evaluated independently from the security conclusion and blocks completion."
    ]
  };
}
