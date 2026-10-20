import { observedRoutePattern } from "./ObservedRoutePatterns.js";
import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { discoveryProposalSchema } from "../contracts/ApplicationDiscoveryContracts.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { hypothesisSource } from "./ApplicationHypothesisBinding.js";
import { readActorObservation } from "./ObservedActorEvidence.js";
import { OBSERVED_LINK_ALGORITHM } from "../../modules/apiGraphql/ObservedLinks.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { scopeSchema } from "../../config/ConfigSchema.js";
export const DISCOVERY_ALGORITHM = "reviewed-native-route-suggestions-v1";
export class ApplicationDiscoveryService {
  constructor(private readonly db: DashboardDatabase) {}
  public preview(org: string, value: unknown) {
    const input = discoveryProposalSchema.parse(value),
      o = hypothesisSource(this.db, org, input.mapRevisionId);
    if (!o.report || !o.scanId || !o.sourceHash) throw Error("WORKBENCH_DISCOVERY_COMPLETE_NATIVE_SOURCE_REQUIRED");
    if (
      !Number.isFinite(Date.parse(o.report.metadata.completedAt)) ||
      Date.now() - Date.parse(o.report.metadata.completedAt) < 0 ||
      Date.now() - Date.parse(o.report.metadata.completedAt) > 1800000
    )
      throw Error("WORKBENCH_DISCOVERY_FRESH_SOURCE_REQUIRED");
    const target = this.db.db
      .prepare("SELECT base_origin,approved_scope_json FROM targets WHERE id=? AND organization_id=?")
      .get(o.input.targetId, org) as { base_origin: string; approved_scope_json: string };
    const matcher = new ScopeMatcher(target.base_origin, scopeSchema.parse(JSON.parse(target.approved_scope_json)));
    let round = 1;
    const visited = new Set(o.input.routes.map((r) => r.url));
    let ancestor = o.input.discoveryBinding;
    while (ancestor) {
      const prior = this.get(org, ancestor.proposalId);
      if (prior.digest !== ancestor.digest) throw Error("WORKBENCH_DISCOVERY_ANCESTOR_CHANGED");
      for (const url of prior.visitedUrls) visited.add(url);
      round++;
      if (round > 3) throw Error("WORKBENCH_DISCOVERY_ROUND_LIMIT");
      ancestor = undefined;
      round = Math.max(round, prior.round + 1);
    }
    if (round > 3) throw Error("WORKBENCH_DISCOVERY_ROUND_LIMIT");
    const candidates = new Map<
        string,
        {
          candidateId: string;
          url: string;
          path: string;
          method: "GET";
          provenance: {
            routeId: string;
            actorId: string;
            checkId: string;
            responseFingerprint: string;
            evidenceFingerprint: string;
          }[];
        }
      >(),
      excluded: { reason: string; count: number }[] = [],
      missingControls: string[] = [];
    const reject = (reason: string, count = 1) => {
      const row = excluded.find((r) => r.reason === reason);
      if (row) row.count += count;
      else excluded.push({ reason, count });
    };
    for (const route of o.input.routes)
      for (const actorId of ["primary", "account-a", "account-b", "anonymous"]) {
        const a = readActorObservation(o, route.id, actorId),
          links = a.check?.observedLinks;
        if (actorId !== "primary" && !readActorObservation(o, route.id, "primary").bindingValid) continue;
        if (!a.bindingValid) {
          missingControls.push(route.id + ":" + actorId + ":" + a.missingControls.join(","));
          continue;
        }
        if (a.request?.decision === "DENIED") {
          reject("DENIED_SOURCE_NO_LINK_COVERAGE");
          continue;
        }
        if (
          !links ||
          links.algorithm !== OBSERVED_LINK_ALGORITHM ||
          links.requestFingerprint !== adaptiveRequestHash(route.url)
        ) {
          missingControls.push(route.id + ":" + actorId + ":LINK_PROVENANCE_UNAVAILABLE");
          continue;
        }
        if (links.truncated) {
          missingControls.push(route.id + ":" + actorId + ":INCOMPLETE_LINK_COVERAGE");
          continue;
        }
        for (const [reason, count] of Object.entries(links.excluded)) reject(reason, count);
        for (const link of links.candidates) {
          const url = new URL(link.path, target.base_origin);
          if (
            !link.path.startsWith("/") ||
            url.origin !== target.base_origin ||
            url.pathname !== link.path ||
            !input.allowedPathPrefixes.some((p) => url.pathname.startsWith(p)) ||
            !matcher.decide(url.href, "GET").allowed
          ) {
            reject("OUTSIDE_REVIEWED_SCOPE");
            continue;
          }
          if (visited.has(url.href)) {
            reject("ALREADY_OBSERVED");
            continue;
          }
          const id = adaptiveDigest({ algorithm: DISCOVERY_ALGORITHM, source: o.sourceBinding, url: url.href }),
            c = candidates.get(id) ?? {
              candidateId: id,
              url: url.href,
              path: link.path,
              method: "GET" as const,
              provenance: []
            };
          c.provenance.push({
            routeId: route.id,
            actorId,
            checkId: a.check!.checkId,
            responseFingerprint: links.responseFingerprint,
            evidenceFingerprint: link.evidenceFingerprint
          });
          candidates.set(id, c);
        }
      }
    const all = [...candidates.values()].sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
    const selected = all.slice(0, input.maxRoutes);
    if (all.length > selected.length) reject("OPERATOR_ROUTE_CAP", all.length - selected.length);
    return {
      algorithm: DISCOVERY_ALGORITHM,
      input,
      source: o.sourceBinding,
      credentials: o.input.credentials,
      targetId: o.input.targetId,
      round,
      visitedUrls: [...visited].sort(),
      candidates: selected.map((c) => ({
        ...c,
        routePattern: observedRoutePattern(c.path),
        advertisedActors: [...new Set(c.provenance.map((p) => p.actorId))].sort(),
        accessPolicyInferred: false as const
      })),
      excluded,
      missingControls,
      coverage: {
        suggested: selected.length,
        eligibleBeforeLimit: all.length,
        observedRoutes: o.input.routes.length,
        actors: 4,
        complete: missingControls.length === 0 && all.length === selected.length
      },
      requestCeiling: input.maxRequests,
      executionAuthority: "NONE",
      policyInferred: false,
      automaticFollow: false,
      scope: "OWNED_LOOPBACK_ONLY"
    };
  }
  public create(org: string, value: unknown, actor: string) {
    const snapshot = this.preview(org, value),
      id = randomUUID(),
      createdAt = new Date().toISOString(),
      expiresAt = new Date(Date.now() + 600000).toISOString(),
      digest = adaptiveDigest(snapshot);
    this.db.db
      .prepare("INSERT INTO application_discovery_proposals VALUES(?,?,?,?,?,?,?,?,?)")
      .run(
        id,
        org,
        snapshot.targetId,
        snapshot.input.mapRevisionId,
        digest,
        JSON.stringify(snapshot),
        actor,
        createdAt,
        expiresAt
      );
    return { proposalId: id, digest, createdAt, expiresAt, ...snapshot };
  }
  public get(org: string, id: string) {
    const row = this.db.db
      .prepare("SELECT * FROM application_discovery_proposals WHERE id=? AND organization_id=?")
      .get(id, org) as Record<string, string> | undefined;
    if (!row) throw Error("WORKBENCH_DISCOVERY_NOT_FOUND");
    const snapshot = JSON.parse(row.snapshot_json!) as ReturnType<ApplicationDiscoveryService["preview"]>;
    if (adaptiveDigest(snapshot) !== row.digest) throw Error("WORKBENCH_DISCOVERY_CUSTODY_INVALID");
    return { proposalId: id, digest: row.digest!, createdAt: row.created_at!, expiresAt: row.expires_at!, ...snapshot };
  }
  public fresh(org: string, id: string) {
    const p = this.get(org, id);
    if (!Number.isFinite(Date.parse(p.expiresAt)) || Date.parse(p.expiresAt) <= Date.now())
      throw Error("WORKBENCH_DISCOVERY_REVIEW_EXPIRED");
    if (adaptiveDigest(this.preview(org, p.input)) !== p.digest) throw Error("WORKBENCH_DISCOVERY_BINDINGS_CHANGED");
    return p;
  }
}
import { createHash } from "node:crypto";
const adaptiveRequestHash = (url: string) => createHash("sha256").update(url).digest("hex");
