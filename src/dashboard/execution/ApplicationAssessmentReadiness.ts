import { z } from "zod";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { applicationAuthorityContext } from "./ApplicationAuthorityBinding.js";
import { identityFingerprint, readActorObservation } from "./ObservedActorEvidence.js";
import { hypothesisSource } from "./ApplicationHypothesisBinding.js";
import { OwnedApplicationIntakeService } from "./OwnedApplicationIntake.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
export const assessmentReadinessQuery = z
  .object({
    targetId: z.string().uuid(),
    primary: z.string().uuid().optional(),
    account_a: z.string().uuid().optional(),
    account_b: z.string().uuid().optional(),
    mapRevisionId: z.string().uuid().optional()
  })
  .strict();
export const OWNER_ASSESSMENT_INPUT = {
  scope:
    "Explicit owner authorization, LOCAL OWNED registered 127.0.0.1 origin, approved GET routes including baseline and identity endpoints. No external host or write operation.",
  actors:
    "Three distinct target-bound saved profiles with nonblank principal, tenant, role and exact identity-verification contracts. Enter secrets only in the credential vault; never upload sessions, HAR bodies or headers.",
  operations:
    "Up to eight explicit GET seeds; typed identity, tenant and at most two non-secret state fields. Three/four-step reference, separate version and optional owner fields must already be observed.",
  policy:
    "Owner declares exact ownership and per-actor expected access. Native observations, policy review and bounded proof each need separate approval. No implicit replay.",
  evaluation:
    "Separate evaluator enrolls fixed cases and families and controls private labels/signing key. Seal predictions and hash-verified evidence before signed label release. Self-authored fixtures are not independent acceptance.",
  remediation:
    "Supply a separately approved GET retest after an owner-applied fix. Compare exact check coverage and export redacted analyst history. UNKNOWN or incomplete evidence cannot close a case."
} as const;
/** Snapshot of existing records only. Does not decrypt, contact targets, approve, retry or manufacture authority. */
export class ApplicationAssessmentReadiness {
  constructor(private db: DashboardDatabase) {}
  get(org: string, value: unknown) {
    const q = assessmentReadinessQuery.parse(value);
    return this.db.db
      .transaction(() => {
        const base = applicationAuthorityContext(this.db, org, q.targetId, []),
          slots = ["primary", "account_a", "account_b"] as const;
        const actors = slots.map((slot) => {
          if (!q[slot])
            return {
              slot,
              status: "MISSING",
              principalFingerprint: null,
              tenantFingerprint: null,
              roleFingerprint: null,
              missing: ["SELECT_TARGET_BOUND_PROFILE"]
            };
          try {
            const c = applicationAuthorityContext(this.db, org, q.targetId, [q[slot]!]).credentials[0]!,
              m = JSON.parse(String(c.safe_identity_summary_json)) as Record<string, unknown>;
            if (
              !m ||
              ["principalId", "tenantId", "role"].some((k) => typeof m[k] !== "string" || !(m[k] as string).trim())
            )
              throw Error("EXPLICIT_ACTOR_METADATA_REQUIRED");
            return {
              slot,
              status: "DECLARED_NOT_NATIVE_VERIFIED",
              principalFingerprint: identityFingerprint(m.principalId as string),
              tenantFingerprint: identityFingerprint(m.tenantId as string),
              roleFingerprint: identityFingerprint(m.role as string),
              missing: [] as string[]
            };
          } catch {
            return {
              slot,
              status: "INVALID_OR_UNAVAILABLE",
              principalFingerprint: null,
              tenantFingerprint: null,
              roleFingerprint: null,
              missing: ["ENABLED_UNEXPIRED_TARGET_BOUND_PROFILE_AND_EXPLICIT_IDENTITY_REQUIRED"]
            };
          }
        });
        const distinct =
          new Set(actors.map((a) => JSON.stringify([a.principalFingerprint, a.tenantFingerprint, a.roleFingerprint])))
            .size === 3 && new Set(slots.map((s) => q[s])).size === 3;
        const actorsReady = actors.every((a) => !a.missing.length) && distinct;
        let observation: {
          status: string;
          scanId: string | null;
          sourceHash: string | null;
          nativeActorRoutePairs: number;
          expectedPairs: number;
          missing: string[];
        } = {
          status: "UNTESTED",
          scanId: null,
          sourceHash: null,
          nativeActorRoutePairs: 0,
          expectedPairs: 0,
          missing: ["SELECT_EXACT_RETAINED_MAP_OR_PREVIEW_THEN_APPROVE_OBSERVATION"]
        };
        if (q.mapRevisionId) {
          const binding = this.db.db
            .prepare("SELECT target_id,input_json FROM application_mapping_revisions WHERE id=? AND organization_id=?")
            .get(q.mapRevisionId, org) as { target_id: string; input_json: string } | undefined;
          if (!binding || binding.target_id !== q.targetId) throw Error("WORKBENCH_READINESS_MAP_UNAVAILABLE");
          const input = JSON.parse(binding.input_json);
          if (slots.some((s) => q[s] !== input.credentials[s]))
            observation = {
              ...observation,
              status: "CONTEXT_MISMATCH",
              missing: ["SELECT_THE_EXACT_SAVED_MAP_ACTOR_PROFILES"]
            };
          else
            try {
              const source = hypothesisSource(this.db, org, q.mapRevisionId),
                cells = source.input.routes.flatMap((r) =>
                  ["primary", "account-a", "account-b", "anonymous"].map((a) => readActorObservation(source, r.id, a))
                );
              const missing = [...new Set(cells.flatMap((c) => c.missingControls))];
              observation = {
                status: source.report && !missing.length ? "NATIVE_OBSERVED_REVIEW_REQUIRED" : source.status,
                scanId: source.scanId ?? null,
                sourceHash: source.sourceHash ?? null,
                nativeActorRoutePairs: cells.filter((c) => c.bindingValid).length,
                expectedPairs: cells.length,
                missing: source.report ? missing : ["COMPLETE_INTEGRITY_CHECKED_NATIVE_REPORT_REQUIRED"]
              };
            } catch {
              observation = {
                ...observation,
                status: "UNKNOWN_OR_STALE",
                missing: ["REVIEW_CHANGED_AUTHORITY_OR_NATIVE_SOURCE_CUSTODY_NO_AUTOMATIC_REPLAY"]
              };
            }
        }
        const intake = new OwnedApplicationIntakeService(this.db).list(org, q.targetId),
          steps = [
            {
              id: "scope",
              status: "REGISTERED_OWNER_DECLARATION",
              next: "Review exact permitted GET scope; registration does not grant execution."
            },
            {
              id: "actors",
              status: actorsReady ? "DECLARED_NOT_NATIVE_VERIFIED" : "ACTION_REQUIRED",
              next: "Save three distinct actor contracts; native identity verification occurs only in separately approved observation."
            },
            {
              id: "intake",
              status: intake.total ? "RETAINED_OFFLINE_METADATA" : "OPTIONAL",
              next: "Import minimized owner evidence or review explicit seeds. Offline receipt is not a verified session."
            },
            {
              id: "observation",
              status: observation.status,
              next: "Inspect native identity, route decisions, typed markers and source hash before declaring policy."
            },
            {
              id: "policy",
              status: "EXPLICIT_REVIEW_REQUIRED",
              next: "Connect already observed references, owner and version fields; declare exact per-actor business policy."
            },
            {
              id: "proof",
              status: "SEPARATE_APPROVAL_REQUIRED",
              next: "Authorize the exact bounded proof, inspect findings/abstentions, compare an approved retest and export analyst history."
            }
          ];
        const result = {
          version: 1,
          targetId: q.targetId,
          classification: String(base.target.classification),
          actors,
          actorsReady,
          distinctActorContexts: distinct,
          observation,
          intake,
          steps,
          ownerInputContract: OWNER_ASSESSMENT_INPUT,
          requestsSent: 0,
          credentialDecryption: false,
          executionAuthority: "NONE",
          nativeCompletionIsSecurityPass: false,
          stateChangingExecution: "HOLD",
          independentEvaluation: "BLOCKED_PENDING_SEPARATE_EVALUATOR",
          fullApplicationAcceptance: false
        };
        return { ...result, snapshotSha256: adaptiveDigest(result) };
      })
      .deferred();
  }
}
