import { applicationIdentityModel } from "../../core/auth/IdentityModel.js";
import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { mappingObservation } from "./ApplicationMappingEvidence.js";
import { mappingContext } from "./ApplicationMappingBinding.js";
import { mapComparisonSchema } from "../contracts/ApplicationSchemaContracts.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
type Observation = ReturnType<typeof mappingObservation>;
function snapshot(o: Observation) {
  const actors = o.report?.scanPlan?.apiGraphql?.actors ?? [];
  return {
    revisionId: o.row.id!,
    revisionDigest: o.row.digest!,
    sourceHash: o.sourceHash ?? null,
    status: o.status,
    schemaProvenance: o.input.schemaBinding ?? null,
    routes: o.input.routes.map((r) => ({
      key: adaptiveDigest({ url: r.url, template: r.pathTemplate, kind: r.kind }),
      routeId: r.id,
      url: r.url,
      template: r.pathTemplate,
      kind: r.kind,
      identityPath: r.identityPath,
      tenantPath: r.tenantPath ?? null,
      cells: ["primary", "account-a", "account-b", "anonymous"].map((actorId) => {
        const actor = actors.find((a) => a.id === actorId),
          c = o.report?.apiGraphql?.checks.find((c) => c.checkId === r.id + "-observe-" + actorId),
          identity =
            actorId === "anonymous"
              ? true
              : actorId === "primary"
                ? o.report?.identityVerification?.primary?.verified
                : actorId === "account-a"
                  ? o.report?.identityVerification?.accountA?.verified
                  : o.report?.identityVerification?.accountB?.verified;
        const known =
          !!actor &&
          identity === true &&
          c?.outcome === "PASS" &&
          ["ALLOWED", "DENIED"].includes(c.requests[0]?.decision ?? "");
        return {
          actorId,
          classification: known ? c!.requests[0]!.decision : "UNKNOWN",
          statusCode: known ? c!.requests[0]!.statusCode : null,
          nativeOutcome: c?.outcome ?? "UNOBSERVED",
          markerTypes: [...new Set([r.identityPath, ...(r.tenantPath ? [r.tenantPath] : [])])].map((path) => ({
            path,
            type: known ? (c?.observedMarkers?.find((m) => m.path === path)?.scalarType ?? "UNOBSERVED") : "UNOBSERVED"
          }))
        };
      })
    }))
  };
}
export function diffApplicationMaps(a: ReturnType<typeof snapshot>, b: ReturnType<typeof snapshot>) {
  if (
    new Set(a.routes.map((r) => r.key)).size !== a.routes.length ||
    new Set(b.routes.map((r) => r.key)).size !== b.routes.length
  )
    throw Error("WORKBENCH_MAP_AMBIGUOUS_ROUTES");
  const complete = a.status === "COMPLETED" && b.status === "COMPLETED";
  const routes = [...new Set([...a.routes.map((r) => r.key), ...b.routes.map((r) => r.key)])].sort().map((key) => {
    const old = a.routes.find((r) => r.key === key),
      now = b.routes.find((r) => r.key === key);
    const membership = !old ? "ADDED_DECLARED_SEED" : !now ? "REMOVED_DECLARED_SEED" : "SHARED_SEED";
    return {
      key,
      url: (now ?? old)!.url,
      membership,
      observation: complete ? "COMPLETE_NATIVE_REPORTS" : "UNKNOWN_INCOMPLETE_EVIDENCE",
      cells:
        !old || !now
          ? []
          : old.cells.map((x) => {
              const y = now.cells.find((c) => c.actorId === x.actorId) ?? {
                actorId: x.actorId,
                classification: "UNKNOWN",
                statusCode: null,
                nativeOutcome: "UNOBSERVED",
                markerTypes: []
              };
              const known = complete && x.classification !== "UNKNOWN" && y.classification !== "UNKNOWN";
              const markerTypes = [
                ...new Set([...x.markerTypes.map((m) => m.path), ...y.markerTypes.map((m) => m.path)])
              ].map((path) => {
                const before = x.markerTypes.find((m) => m.path === path)?.type,
                  after = y.markerTypes.find((m) => m.path === path)?.type;
                return {
                  path,
                  before: before ?? "UNOBSERVED",
                  after: after ?? "UNOBSERVED",
                  change:
                    known && before && after && before !== "UNOBSERVED" && after !== "UNOBSERVED"
                      ? before === after
                        ? "UNCHANGED"
                        : "TYPE_CHANGED"
                      : "UNKNOWN"
                };
              });
              return {
                actorId: x.actorId,
                before: x,
                after: y,
                accessChange: known
                  ? x.classification === y.classification
                    ? "UNCHANGED"
                    : "CHANGED_HYPOTHESIS"
                  : "UNKNOWN",
                responseChange: known
                  ? x.statusCode === y.statusCode
                    ? "UNCHANGED"
                    : "CHANGED_HYPOTHESIS"
                  : "UNKNOWN",
                markerTypes
              };
            })
    };
  });
  return {
    status: complete ? "OBSERVED_DIFFERENCES" : "UNKNOWN",
    routes,
    differencesAreHypotheses: true as const,
    authorizationPolicyInferred: false as const,
    verifiedApplicationPass: false as const
  };
}
export class ApplicationMapComparisonService {
  constructor(private readonly db: DashboardDatabase) {}
  public create(org: string, value: unknown, actor: string) {
    return this.db.db.transaction(() => this.capture(org, value, actor)).immediate();
  }
  private capture(org: string, value: unknown, actor: string) {
    const input = mapComparisonSchema.parse(value);
    if (input.baselineRevisionId === input.currentRevisionId) throw Error("WORKBENCH_MAP_DISTINCT_REVISIONS_REQUIRED");
    const a = mappingObservation(this.db, org, input.baselineRevisionId),
      b = mappingObservation(this.db, org, input.currentRevisionId);
    if (
      a.row.target_id !== b.row.target_id ||
      applicationIdentityModel(a.input.identityModel) !== applicationIdentityModel(b.input.identityModel) ||
      a.row.context_digest !== b.row.context_digest ||
      adaptiveDigest(a.input.credentials) !== adaptiveDigest(b.input.credentials) ||
      mappingContext(this.db, org, a.input.targetId, Object.values(a.input.credentials)).digest !== a.row.context_digest
    )
      throw Error("WORKBENCH_MAP_IDENTICAL_AUTHORITY_CONTEXT_REQUIRED");
    const baseline = snapshot(a),
      current = snapshot(b),
      comparison = { baseline, current, ...diffApplicationMaps(baseline, current) },
      digest = adaptiveDigest(comparison),
      id = randomUUID(),
      createdAt = new Date().toISOString();
    this.db.db
      .prepare("INSERT INTO application_map_comparisons VALUES(?,?,?,?,?,?,?,?)")
      .run(
        id,
        org,
        input.baselineRevisionId,
        input.currentRevisionId,
        digest,
        JSON.stringify(comparison),
        actor,
        createdAt
      );
    return { comparisonId: id, digest, createdAt, ...comparison };
  }
  public result(org: string, id: string) {
    const row = this.db.db
      .prepare("SELECT * FROM application_map_comparisons WHERE id=? AND organization_id=?")
      .get(id, org) as Record<string, string> | undefined;
    if (!row) throw Error("WORKBENCH_MAP_COMPARISON_NOT_FOUND");
    const value = JSON.parse(row.snapshot_json!) as ReturnType<typeof this.create>;
    if (adaptiveDigest(value) !== row.digest) throw Error("WORKBENCH_MAP_COMPARISON_CUSTODY_INVALID");
    return { ...value, comparisonId: id, digest: row.digest!, createdAt: row.created_at! };
  }
}
