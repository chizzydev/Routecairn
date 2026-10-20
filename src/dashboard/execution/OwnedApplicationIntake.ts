import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import {
  applicationMappingInputSchema,
  type ApplicationMappingInput
} from "../contracts/ApplicationMappingContracts.js";
import { ownedApplicationIntakeSchema } from "../contracts/OwnedApplicationIntakeContracts.js";
import { applicationAuthorityContext } from "./ApplicationAuthorityBinding.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { identityFingerprint } from "./ObservedActorEvidence.js";
import { createHash } from "node:crypto";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
const sha = (v: string) => createHash("sha256").update(v).digest("hex");
function validatedOwnedIntakeContext(
  db: DashboardDatabase,
  org: string,
  target: string,
  credentials: readonly string[]
) {
  const context = applicationAuthorityContext(db, org, target, credentials),
    identities = context.credentials.map(
      (c) => JSON.parse(String(c.safe_identity_summary_json)) as Record<string, unknown> | null
    );
  if (
    identities.some(
      (m) => !m || ["principalId", "tenantId", "role"].some((k) => typeof m[k] !== "string" || !(m[k] as string).trim())
    )
  )
    throw Error("WORKBENCH_INTAKE_EXPLICIT_ACTOR_METADATA_REQUIRED");
  if (new Set(identities.map((m) => JSON.stringify([m!.principalId, m!.tenantId, m!.role]))).size !== 3)
    throw Error("WORKBENCH_INTAKE_DISTINCT_ACTOR_CONTEXTS_REQUIRED");
  return context;
}
/** Minimized offline metadata only. Uploaded bodies, headers, cookies and raw HAR are refused. */
export class OwnedApplicationIntakeService {
  list(org: string, targetId: string) {
    return this.db.db
      .transaction(() => {
        if (!this.db.db.prepare("SELECT 1 FROM targets WHERE id=? AND organization_id=?").get(targetId, org))
          throw Error("WORKBENCH_INTAKE_TARGET_UNAVAILABLE");
        const records = this.db.db
            .prepare(
              "SELECT id revisionId,digest,created_at createdAt,json_extract(snapshot_json,'$.artifactSha256') artifactSha256 FROM application_owned_intakes WHERE organization_id=? AND target_id=? ORDER BY created_at DESC,id DESC LIMIT 20"
            )
            .all(org, targetId) as { revisionId: string; digest: string; createdAt: string; artifactSha256: string }[],
          total = (
            this.db.db
              .prepare("SELECT count(*) n FROM application_owned_intakes WHERE organization_id=? AND target_id=?")
              .get(org, targetId) as { n: number }
          ).n;
        return { records, total, truncated: records.length < total, executionAuthority: "NONE", requestsSent: 0 };
      })
      .deferred();
  }
  get(org: string, id: string) {
    return this.db.db
      .transaction(() => {
        const row = this.db.db
          .prepare("SELECT * FROM application_owned_intakes WHERE id=? AND organization_id=?")
          .get(id, org) as
          { target_id: string; digest: string; context_digest: string; snapshot_json: string } | undefined;
        if (!row) throw Error("WORKBENCH_INTAKE_UNAVAILABLE");
        const raw = JSON.parse(row.snapshot_json);
        if (adaptiveDigest(raw) !== row.digest) throw Error("WORKBENCH_INTAKE_CUSTODY_CHANGED");
        const s = raw as Omit<
            ReturnType<OwnedApplicationIntakeService["create"]>,
            "revisionId" | "digest" | "freshness"
          >,
          draft = applicationMappingInputSchema.parse(s.draft);
        if (
          draft.targetId !== row.target_id ||
          s.contextDigest !== row.context_digest ||
          !/^[a-f0-9]{64}$/.test(s.artifactSha256)
        )
          throw Error("WORKBENCH_INTAKE_CUSTODY_CHANGED");
        const metadata = ownedApplicationIntakeSchema.shape.artifact.parse({
          version: 1,
          kind: "OWNER_EVIDENCE_EXPORT",
          origin: new URL(draft.routes[0]!.url).origin,
          exportSha256: s.exportSha256,
          capturedAt: s.capturedAt,
          provenance: s.provenance,
          actors: s.actorDeclarations,
          routes: draft.routes
        });
        let freshness: "CURRENT" | "STALE" = "STALE";
        try {
          if (
            adaptiveDigest(
              validatedOwnedIntakeContext(this.db, org, draft.targetId, Object.values(draft.credentials))
            ) === row.context_digest
          )
            freshness = "CURRENT";
        } catch {
          /* Historical declarations remain readable, never restored execution authority. */
        }
        return {
          revisionId: id,
          digest: row.digest,
          version: 1,
          artifactSha256: s.artifactSha256,
          exportSha256: metadata.exportSha256,
          provenance: metadata.provenance,
          provenanceAuthority: "OWNER_DECLARATION_NOT_INDEPENDENT_ATTESTATION",
          capturedAt: metadata.capturedAt,
          actorDeclarations: metadata.actors,
          contextDigest: s.contextDigest,
          identityStatus: "DECLARED_NOT_NATIVE_VERIFIED",
          sessionStatus: "OWNER_SUPPLIED_EVIDENCE_HASH_NOT_INDEPENDENTLY_AUTHENTICATED",
          missing: [
            "FRESH_NATIVE_IDENTITY_AND_ROUTE_OBSERVATIONS",
            "EXPLICIT_OWNER_BUSINESS_POLICY",
            "SEPARATE_EXACT_NATIVE_CONSENT"
          ],
          executionAuthority: "NONE",
          requestsSent: 0,
          freshness,
          draft: { ...draft, intakeBinding: { revisionId: id, digest: row.digest } }
        };
      })
      .deferred();
  }

  constructor(private db: DashboardDatabase) {}
  create(org: string, value: unknown, actor: string) {
    const input = ownedApplicationIntakeSchema.parse(value);
    return this.db.db
      .transaction(() => {
        const context = validatedOwnedIntakeContext(this.db, org, input.targetId, Object.values(input.credentials)),
          origin = String(context.target.base_origin),
          artifact = input.artifact;
        if (
          artifact.origin !== origin ||
          Date.parse(artifact.capturedAt) > Date.now() + 60000 ||
          Date.parse(artifact.capturedAt) < Date.now() - 7 * 86400000
        )
          throw Error("WORKBENCH_INTAKE_EXACT_RECENT_ORIGIN_REQUIRED");
        if (
          new Set(Object.values(input.credentials)).size !== 3 ||
          new Set(artifact.actors.map((a) => a.slot)).size !== 3
        )
          throw Error("WORKBENCH_INTAKE_DISTINCT_ACTORS_REQUIRED");
        for (const a of artifact.actors) {
          const c = context.credentials.find((c) => c.id === input.credentials[a.slot])!,
            m = JSON.parse(String(c.safe_identity_summary_json));
          if (
            identityFingerprint(String(m.principalId)) !== a.principalFingerprint ||
            identityFingerprint(String(m.tenantId)) !== a.tenantFingerprint ||
            identityFingerprint(String(m.role)) !== a.roleFingerprint
          )
            throw Error("WORKBENCH_INTAKE_ACTOR_DECLARATION_MISMATCH");
        }
        const matcher = new ScopeMatcher(
          origin,
          scopeSchema.parse(JSON.parse(String(context.target.approved_scope_json)))
        );
        for (const r of artifact.routes) {
          const u = new URL(r.url);
          if (
            u.origin !== origin ||
            u.href !== origin + r.pathTemplate ||
            u.search ||
            u.hash ||
            u.username ||
            u.password ||
            u.pathname.includes("%") ||
            !/^\/[A-Za-z0-9_./-]*$/.test(u.pathname) ||
            u.pathname.split("/").some((s) => s === "." || s === "..") ||
            !matcher.decide(u.href, "GET").allowed
          )
            throw Error("WORKBENCH_INTAKE_LITERAL_SCOPED_GET_REQUIRED");
        }
        if (
          new Set(artifact.routes.map((r) => r.id)).size !== artifact.routes.length ||
          new Set(artifact.routes.map((r) => r.url)).size !== artifact.routes.length
        )
          throw Error("WORKBENCH_INTAKE_DUPLICATE_OPERATION");
        const draft: ApplicationMappingInput = {
          targetId: input.targetId,
          credentials: input.credentials,
          routes: artifact.routes,
          identityContextConfirmed: true,
          readOnlyRoutesConfirmed: true
        };
        const snapshot = {
          version: 1,
          artifactSha256: sha(JSON.stringify(artifact)),
          exportSha256: artifact.exportSha256,
          provenance: artifact.provenance,
          provenanceAuthority: "OWNER_DECLARATION_NOT_INDEPENDENT_ATTESTATION",
          capturedAt: artifact.capturedAt,
          actorDeclarations: artifact.actors,
          contextDigest: adaptiveDigest(context),
          draft,
          identityStatus: "DECLARED_NOT_NATIVE_VERIFIED",
          sessionStatus: "OWNER_SUPPLIED_EVIDENCE_HASH_NOT_INDEPENDENTLY_AUTHENTICATED",
          missing: [
            "FRESH_NATIVE_IDENTITY_AND_ROUTE_OBSERVATIONS",
            "EXPLICIT_OWNER_BUSINESS_POLICY",
            "SEPARATE_EXACT_NATIVE_CONSENT"
          ],
          executionAuthority: "NONE",
          requestsSent: 0
        };
        const id = randomUUID(),
          digest = adaptiveDigest(snapshot);
        this.db.db
          .prepare("INSERT INTO application_owned_intakes VALUES(?,?,?,?,?,?,?,?)")
          .run(
            id,
            org,
            input.targetId,
            snapshot.contextDigest,
            digest,
            JSON.stringify(snapshot),
            actor,
            new Date().toISOString()
          );
        return {
          revisionId: id,
          freshness: "CURRENT" as const,
          digest,
          ...snapshot,
          draft: { ...draft, intakeBinding: { revisionId: id, digest } }
        };
      })
      .immediate();
  }
}
export function assertOwnedApplicationIntakeBinding(
  db: DashboardDatabase,
  org: string,
  input: ApplicationMappingInput
) {
  const b = input.intakeBinding;
  if (!b) return;
  const r = db.db
    .prepare("SELECT * FROM application_owned_intakes WHERE id=? AND organization_id=? AND target_id=?")
    .get(b.revisionId, org, input.targetId) as
    { digest: string; context_digest: string; snapshot_json: string } | undefined;
  if (!r || r.digest !== b.digest) throw Error("WORKBENCH_INTAKE_BINDING_UNAVAILABLE");
  const s = JSON.parse(r.snapshot_json),
    { intakeBinding: _b, ...draft } = input;
  if (
    adaptiveDigest(s) !== r.digest ||
    adaptiveDigest(s.draft) !== adaptiveDigest(draft) ||
    adaptiveDigest(validatedOwnedIntakeContext(db, org, input.targetId, Object.values(input.credentials))) !==
      r.context_digest
  )
    throw Error("WORKBENCH_INTAKE_BINDINGS_CHANGED");
}
