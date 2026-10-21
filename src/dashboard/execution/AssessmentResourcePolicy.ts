import { createHash } from "node:crypto";
import { z } from "zod";
import { actorIdSchema, identityFingerprint, type ActorRegistry } from "../../core/auth/ActorRegistry.js";
import { collectionContractSchema } from "../../modules/apiGraphql/CollectionContracts.js";
import { parseSafeFieldPath } from "../../modules/fieldExposureTesting/SafeFieldPath.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
export const reviewedReadPath = z
  .string()
  .max(300)
  .regex(/^\/[A-Za-z0-9_./-]*$/)
  .refine(
    (p) => !p.includes("//") && !p.split("/").some((s) => s === "." || s === ".."),
    "Canonical exact path required"
  );
const field = z
  .string()
  .min(1)
  .max(80)
  .refine((p) => {
    try {
      parseSafeFieldPath(p, { maxDepth: 8, maxArrayIndex: 64, code: "POLICY_FIELD_INVALID" });
      return !/(?:password|token|secret|cookie|authorization|session|__proto__|prototype|constructor)/i.test(p);
    } catch {
      return false;
    }
  });
const base = z.object({
  id: actorIdSchema.refine((id) => id.length <= 40, "Bounded compiled policy ID required"),
  path: reviewedReadPath,
  policyReference: z.string().min(12).max(240),
  reviewed: z.literal(true),
  allowedStatuses: z.array(z.number().int().min(200).max(299)).min(1).max(8).default([200]),
  deniedStatuses: z.array(z.number().int().min(400).max(499)).min(1).max(8).default([401, 403, 404])
});
export const assessmentResourcePolicySchema = z.discriminatedUnion("kind", [
  base
    .extend({
      kind: z.literal("OBJECT_OWNERSHIP"),
      pathTemplate: z.string().min(3).max(300),
      ownerActorId: actorIdSchema,
      ownerPath: field,
      ownerValue: z.string().min(1).max(120)
    })
    .strict(),
  base.extend({ kind: z.literal("COLLECTION_OWNERSHIP"), collection: collectionContractSchema }).strict(),
  base
    .extend({
      kind: z.literal("FIELD_EXPOSURE"),
      fieldPath: field,
      permittedActorIds: z.array(actorIdSchema).min(1).max(8),
      roleAssuranceRequired: z.boolean().default(false)
    })
    .strict(),
  base
    .extend({
      kind: z.literal("BUSINESS_READ"),
      actorIds: z.array(actorIdSchema).min(1).max(8),
      prerequisiteResourceId: actorIdSchema.optional(),
      markerPath: field,
      markerValue: z.union([z.string().min(1).max(120), z.number().finite(), z.boolean()])
    })
    .strict(),
  base.extend({ kind: z.literal("SESSION_READ"), actorIds: z.array(actorIdSchema).min(1).max(8) }).strict()
]);
export type AssessmentResourcePolicy = z.infer<typeof assessmentResourcePolicySchema>;
/** A versioned adapter into the existing native API engine, never a new executor. */
export function compileAssessmentResources(
  resources: readonly AssessmentResourcePolicy[],
  actors: ActorRegistry["actors"],
  origin: string,
  scope: RouteCairnScope
) {
  const workflows: ActorRegistry["workflows"] = [],
    routes: Array<Record<string, unknown>> = [],
    checks: Array<Record<string, unknown>> = [];
  const ids = actors.map((a) => a.id),
    seen = new Set<string>();
  for (const r of resources) {
    if (seen.has(r.id)) throw Error("RESOURCE_POLICY_DUPLICATE_ID");
    const url = new URL(r.path, origin);
    if (
      url.origin !== origin ||
      url.pathname !== r.path ||
      !new ScopeMatcher(origin, scope).decide(url.href, "GET").allowed
    )
      throw Error("RESOURCE_POLICY_SCOPE_REQUIRED");
    if (r.kind === "COLLECTION_OWNERSHIP" && r.collection.maxResponseBytes > 16384)
      throw Error("RESOURCE_POLICY_RESPONSE_BUDGET_EXCEEDED");
    const selected = "actorIds" in r ? r.actorIds : ids;
    if (new Set(selected).size !== selected.length || selected.some((id) => !ids.includes(id)))
      throw Error("RESOURCE_POLICY_ACTOR_REQUIRED");
    if (
      !selected.length ||
      ((r.kind === "OBJECT_OWNERSHIP" || r.kind === "COLLECTION_OWNERSHIP") && selected.length < 2)
    )
      throw Error("RESOURCE_POLICY_LEGITIMATE_ACTORS_REQUIRED");
    if (
      r.kind === "OBJECT_OWNERSHIP" &&
      (!ids.includes(r.ownerActorId) ||
        actors.find((a) => a.id === r.ownerActorId)?.principalFingerprint !== identityFingerprint(r.ownerValue))
    )
      throw Error("RESOURCE_POLICY_EXACT_OWNER_PRINCIPAL_REQUIRED");
    if (
      r.kind === "FIELD_EXPOSURE" &&
      (new Set(r.permittedActorIds).size !== r.permittedActorIds.length ||
        r.permittedActorIds.some((id) => !ids.includes(id)))
    )
      throw Error("RESOURCE_POLICY_PERMITTED_ACTOR_REQUIRED");
    if (r.kind === "BUSINESS_READ" && r.prerequisiteResourceId) {
      const prior = resources.find((p) => p.id === r.prerequisiteResourceId);
      if (
        !seen.has(r.prerequisiteResourceId) ||
        prior?.kind !== "BUSINESS_READ" ||
        r.actorIds.some((id) => !prior.actorIds.includes(id))
      )
        throw Error("RESOURCE_POLICY_PRIOR_SAME_ACTOR_READ_REQUIRED");
    }
    const id = "resource-" + r.id,
      policySha = createHash("sha256")
        .update("routecairn-reviewed-resource-v1\0")
        .update(JSON.stringify(r))
        .digest("hex");
    workflows.push({
      id,
      family:
        r.kind === "SESSION_READ"
          ? "AUTHENTICATED_OBSERVATION"
          : r.kind === "FIELD_EXPOSURE" && r.roleAssuranceRequired
            ? "ROLE_COMPARISON"
            : r.kind === "BUSINESS_READ" || r.kind === "FIELD_EXPOSURE"
              ? "PRINCIPAL_OBSERVATION"
              : "OWNERSHIP_COMPARISON",
      actorIds: selected,
      ownerPolicySha256: policySha,
      reviewed: true,
      applicable: true
    });
    routes.push({
      id,
      safeAlias: r.id,
      protocol: "REST",
      kind: r.kind === "OBJECT_OWNERSHIP" ? "OBJECT" : r.kind === "COLLECTION_OWNERSHIP" ? "COLLECTION" : "FUNCTION",
      url: url.href,
      ...(r.kind === "OBJECT_OWNERSHIP" ? { pathTemplate: r.pathTemplate } : {}),
      objectType: r.kind,
      functionName: r.id,
      documentedMethods: ["GET"]
    });
    for (const actorId of selected) {
      checks.push({
        id: id + "-" + actorId,
        matrixId: id,
        label: "Reviewed " + r.kind + " · " + actorId,
        kind:
          r.kind === "OBJECT_OWNERSHIP" || r.kind === "COLLECTION_OWNERSHIP"
            ? "OBJECT_AUTHORIZATION"
            : r.kind === "FIELD_EXPOSURE"
              ? "FIELD_AUTHORIZATION"
              : "FUNCTION_AUTHORIZATION",
        routeId: id,
        actorId,
        requireVerifiedIdentity: r.kind !== "SESSION_READ",
        request: { method: "GET" },
        ...(r.kind === "BUSINESS_READ" && r.prerequisiteResourceId
          ? { prerequisiteCheckIds: ["resource-" + r.prerequisiteResourceId + "-" + actorId] }
          : {}),
        response: {
          expectedDecision:
            r.kind === "SESSION_READ"
              ? "OBSERVE"
              : r.kind === "OBJECT_OWNERSHIP" && actorId !== r.ownerActorId
                ? "DENY"
                : "ALLOW",
          allowedStatuses: r.allowedStatuses,
          deniedStatuses: r.deniedStatuses,
          ...(r.kind === "OBJECT_OWNERSHIP" ? { identity: { path: r.ownerPath, expectedValue: r.ownerValue } } : {}),
          ...(r.kind === "COLLECTION_OWNERSHIP" ? { collection: r.collection } : {}),
          ...(r.kind === "FIELD_EXPOSURE"
            ? {
                fieldRules: [
                  {
                    path: r.fieldPath,
                    classification: "PERSONAL",
                    expectation: r.permittedActorIds.includes(actorId) ? "MUST_BE_PRESENT" : "MUST_BE_ABSENT"
                  }
                ]
              }
            : {}),
          ...(r.kind === "BUSINESS_READ"
            ? { stateMarkers: [{ path: r.markerPath, expectedValue: r.markerValue }] }
            : {})
        }
      });
    }
    seen.add(r.id);
  }
  return { adapterVersion: 1 as const, workflows, routes, checks, paths: resources.map((r) => r.path) };
}
