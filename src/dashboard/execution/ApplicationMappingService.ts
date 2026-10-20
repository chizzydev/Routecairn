import { assertOwnedApplicationIntakeBinding } from "./OwnedApplicationIntake.js";
import { assertApplicationDiscoveryBinding } from "./ApplicationDiscoveryBinding.js";
import { assertApplicationSchemaBinding } from "./ApplicationSchemaService.js";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import type { ScanExecutionService } from "./ScanExecutionService.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { TargetRepository } from "../db/DashboardRepositories.js";
import {
  applicationMappingInputSchema,
  applicationMappingPolicySchema
} from "../contracts/ApplicationMappingContracts.js";
import { apiGraphqlInputSchema } from "../../modules/apiGraphql/ApiGraphqlPlanner.js";
import { scanStudioSchema } from "../contracts/ScanStudioSchemas.js";
import { mappingContext } from "./ApplicationMappingBinding.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { mappingObservation } from "./ApplicationMappingEvidence.js";
import { AuthorizationWorkbenchService } from "./AuthorizationWorkbenchService.js";
import { buildAdaptiveInventory, synthesizeAdaptiveRecommendations } from "./AdaptiveSynthesisCore.js";
import { projectAdaptiveSecurityCases } from "./AdaptiveSecurityCaseProjection.js";
import { projectAdaptiveObservedInputs } from "./AdaptiveObservedInputProjection.js";
export class ApplicationMappingService {
  constructor(
    private readonly db: DashboardDatabase,
    private readonly vault: CredentialVault,
    private readonly execution: ScanExecutionService
  ) {}
  public async preview(org: string, value: unknown) {
    const input = applicationMappingInputSchema.parse(value),
      context = mappingContext(this.db, org, input.targetId, Object.values(input.credentials)),
      target = new TargetRepository(this.db).get(input.targetId)!;
    assertOwnedApplicationIntakeBinding(this.db, org, input);
    assertApplicationSchemaBinding(this.db, org, input);
    const discoveryBudget = assertApplicationDiscoveryBinding(this.db, org, input);
    if (new Set(Object.values(input.credentials)).size !== 3) throw Error("WORKBENCH_MAPPING_DISTINCT_ACTORS_REQUIRED");
    const matcher = new ScopeMatcher(target.baseOrigin, scopeSchema.parse(target.approvedScope)),
      intents: Array<{ purpose: string; actorId: string; method: "GET"; url: string; credentialProfileId?: string }> = [
        { purpose: "CORE_BASELINE", actorId: "anonymous", method: "GET", url: new URL("/", target.baseOrigin).href }
      ];
    const actors = Object.entries(input.credentials).map(([slot, id]) => {
      const c = this.vault.getSummary(id, org);
      if (!c) throw Error("WORKBENCH_MAPPING_ACTOR_METADATA_REQUIRED");
      const m = c.safeIdentitySummary,
        secret = this.vault.decryptForHealthCheck(id),
        identity = secret.identityVerification;
      if (
        typeof m.principalId !== "string" ||
        typeof m.tenantId !== "string" ||
        typeof m.role !== "string" ||
        !identity?.tenantFieldPath ||
        !identity.roleFieldPath
      )
        throw Error("WORKBENCH_MAPPING_VERIFIED_IDENTITY_CONTRACT_REQUIRED");
      const url = new URL(identity.endpoint, target.baseOrigin);
      if (
        url.origin !== target.baseOrigin ||
        url.username ||
        url.password ||
        url.search ||
        url.hash ||
        !matcher.decide(url.href, "GET").allowed
      )
        throw Error("WORKBENCH_MAPPING_IDENTITY_SCOPE_REQUIRED");
      const actorId = slot.replaceAll("_", "-");
      intents.push({
        purpose: "VERIFY_PRINCIPAL_TENANT_ROLE",
        actorId,
        method: "GET",
        url: url.href,
        credentialProfileId: id
      });
      return {
        id: actorId,
        safeAlias: c.safeAlias,
        authSlot: slot as "primary" | "account_a" | "account_b",
        relationship:
          slot === "primary" ? "DECLARED_PRIMARY" : slot === "account_a" ? "DECLARED_ACCOUNT_A" : "DECLARED_ACCOUNT_B",
        principalId: m.principalId,
        tenantId: m.tenantId,
        role: m.role
      };
    });
    if (new Set(actors.map((a) => JSON.stringify([a.principalId, a.tenantId, a.role]))).size !== actors.length)
      throw Error("WORKBENCH_MAPPING_DISTINCT_ACTOR_CONTEXTS_REQUIRED");
    const anonymous = {
      id: "anonymous",
      safeAlias: "Anonymous",
      authSlot: "anonymous" as const,
      relationship: "PUBLIC"
    };
    const allActors = [...actors, anonymous];
    const ids = new Set<string>();
    const routes = input.routes.map((r) => {
      const url = new URL(r.url),
        parts = r.pathTemplate.split("/"),
        actual = url.pathname.split("/");
      if (
        ids.has(r.id) ||
        url.origin !== target.baseOrigin ||
        url.username ||
        url.password ||
        url.search ||
        url.hash ||
        url.pathname.includes("%") ||
        !r.pathTemplate.startsWith("/") ||
        parts.length !== actual.length ||
        parts.some((p, i) =>
          p.startsWith(":")
            ? !/^:[A-Za-z][A-Za-z0-9_]*$/.test(p) || !/^[A-Za-z0-9._-]{1,80}$/.test(actual[i] ?? "")
            : p !== actual[i]
        ) ||
        !matcher.decide(url.href, "GET").allowed
      )
        throw Error("WORKBENCH_MAPPING_EXACT_SCOPED_ROUTE_REQUIRED");
      ids.add(r.id);
      for (const a of allActors)
        intents.push({ purpose: r.id + "-observe-" + a.id, actorId: a.id, method: "GET", url: url.href });
      return {
        id: r.id,
        safeAlias: r.id,
        protocol: "REST" as const,
        kind: r.kind,
        url: url.href,
        pathTemplate: r.pathTemplate,
        objectType: r.kind === "OBJECT" ? "operator-declared-object" : undefined,
        functionName: r.kind === "FUNCTION" ? r.id : undefined,
        documentedMethods: ["GET"]
      };
    });
    if (!matcher.decide(intents[0]!.url, "GET").allowed) throw Error("WORKBENCH_MAPPING_BASELINE_SCOPE_REQUIRED");
    const apiGraphql = apiGraphqlInputSchema.parse({
      schemaVersion: 1,
      maxRequests: discoveryBudget?.engineRequests ?? 32,
      maxResponseBytes: 8192,
      actors: allActors,
      routes,
      checks: input.routes.flatMap((r) =>
        allActors.map((a) => ({
          id: r.id + "-observe-" + a.id,
          matrixId: r.id,
          label: "Explicitly permitted native observation",
          kind: r.kind === "FUNCTION" ? "FUNCTION_AUTHORIZATION" : "OBJECT_AUTHORIZATION",
          routeId: r.id,
          actorId: a.id,
          requireVerifiedIdentity: true,
          request: { method: "GET" },
          response: {
            expectedDecision: "OBSERVE",
            observationPaths: [
              ...new Set([r.identityPath, ...(r.tenantPath ? [r.tenantPath] : []), ...(r.statePaths ?? [])])
            ]
          }
        }))
      )
    });
    const request: DashboardScanCreateRequest = {
      target: target.baseOrigin,
      targetId: target.id,
      ...(target.projectId ? { projectId: target.projectId } : {}),
      profile: "quick",
      includeModules: ["api-graphql-authorization"],
      maxRequests: discoveryBudget?.globalRequests ?? 40,
      cleanupReservedRequests: 0,
      rateLimitPerSecond: Math.min(20, Number(target.approvedScope.rateLimitPerSecond)),
      concurrency: 1,
      authorizationDeclaration: "Explicit owned loopback non-mutating GET observation approval",
      credentialProfileId: input.credentials.primary,
      credentialProfileAId: input.credentials.account_a,
      credentialProfileBId: input.credentials.account_b,
      apiGraphql,
      studio: scanStudioSchema.parse({
        version: 1,
        scanName: "Guided authenticated application observation",
        authorization: { category: "OWNED", confirmed: true },
        scope: target.approvedScope,
        authentication: { mode: "public" }
      })
    };
    const preview = await this.execution.preview(request);
    if (!preview.credentialReadiness.ready) throw Error("WORKBENCH_MAPPING_CREDENTIAL_READINESS_BLOCKED");
    return {
      schemaVersion: 1,
      input,
      request,
      contextDigest: context.digest,
      digest: adaptiveDigest({
        input,
        contextDigest: context.digest,
        request,
        previewIdentity: preview.previewIdentity
      }),
      preview,
      transportIntents: intents,
      actors: allActors.map((a) => ({
        id: a.id,
        alias: a.safeAlias,
        slot: a.authSlot,
        role: "role" in a ? a.role : undefined,
        tenantId: "tenantId" in a ? a.tenantId : undefined,
        principalId: "principalId" in a ? a.principalId : undefined,
        identityState: "SAVED_METADATA_REQUIRES_NATIVE_VERIFICATION"
      })),
      proofBudget: {
        totalRequestCeiling: discoveryBudget?.globalRequests ?? 40,
        perEngineCeiling: discoveryBudget?.engineRequests ?? 32,
        checks: apiGraphql.checks.length,
        identityRequests: 3,
        maxResponseBytes: 8192
      },
      classification: "EXPLICIT_OBSERVATION_APPROVAL_REQUIRED",
      trustedDiscoveryExecution: false
    };
  }
  public async create(org: string, value: unknown, actor: string) {
    const p = await this.preview(org, value),
      id = randomUUID(),
      now = new Date().toISOString(),
      expires = new Date(Date.now() + 600000).toISOString();
    this.db.db
      .transaction(() => {
        const v = (
          this.db.db
            .prepare("SELECT COALESCE(MAX(version),0)+1 n FROM application_mapping_revisions WHERE target_id=?")
            .get(p.input.targetId) as { n: number }
        ).n;
        this.db.db
          .prepare("INSERT INTO application_mapping_revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
          .run(
            id,
            org,
            p.input.targetId,
            v,
            JSON.stringify(p.input),
            JSON.stringify(p.request),
            p.contextDigest,
            p.digest,
            p.preview.previewIdentity,
            actor,
            now,
            expires,
            JSON.stringify(p)
          );
      })
      .immediate();
    return { ...p, revisionId: id, expiresAt: expires };
  }
  public async execute(org: string, id: string, digest: string, actor: string) {
    const o = mappingObservation(this.db, org, id),
      row = o.row;
    if (row.digest !== digest) throw Error("WORKBENCH_MAPPING_STALE_REVIEW");
    const prior = this.db.db
      .prepare("SELECT requested_by FROM application_mapping_dispatches WHERE revision_id=?")
      .get(id) as { requested_by: string } | undefined;
    if (prior) {
      if (prior.requested_by !== actor) throw Error("WORKBENCH_MAPPING_CONSUMED_BY_ANOTHER_OPERATOR");
      return { scanId: o.scanId ?? null, status: o.scanId ? "ALREADY_RECORDED" : "UNKNOWN", replayed: false };
    }
    if (!Number.isFinite(Date.parse(row.expires_at!)) || Date.parse(row.expires_at!) <= Date.now())
      throw Error("WORKBENCH_MAPPING_STALE_REVIEW");
    const fresh = await this.preview(org, o.input);
    if (fresh.digest !== digest) throw Error("WORKBENCH_MAPPING_BINDINGS_CHANGED");
    this.db.db
      .prepare("INSERT INTO application_mapping_dispatches VALUES(?,?,?)")
      .run(id, actor, new Date().toISOString());
    const request = JSON.parse(row.request_json!) as DashboardScanCreateRequest;
    request.applicationMappingBinding = { revisionId: id, digest };
    const scanId = await this.execution.enqueue(request, undefined, undefined, org);
    this.db.db
      .prepare("INSERT INTO application_mapping_acknowledgements VALUES(?,?,?)")
      .run(id, scanId, new Date().toISOString());
    return { scanId, status: "QUEUED", replayed: false };
  }
  public result(org: string, id: string) {
    const o = mappingObservation(this.db, org, id),
      report = o.report;
    const review = JSON.parse(o.row.review_json!) as Awaited<ReturnType<ApplicationMappingService["create"]>>;
    const inventory = report ? buildAdaptiveInventory(report, []) : undefined,
      recommendations = report && inventory ? synthesizeAdaptiveRecommendations(report, inventory, []) : undefined;
    return {
      ...review,
      revisionId: id,
      expiresAt: o.row.expires_at,
      scanId: o.scanId,
      status: o.status,
      failureReason: o.failureReason,
      sourceHash: o.sourceHash,
      observations: report
        ? o.input.routes.map((route) => ({
            routeId: route.id,
            exactUrl: route.url,
            template: route.pathTemplate,
            kind: route.kind,
            provenance: o.input.discoveryBinding
              ? "REVIEWED_NATIVE_LINK_WITH_NATIVE_RESPONSE_EVIDENCE"
              : o.input.schemaBinding
                ? "REVIEWED_SCHEMA_WITH_NATIVE_RESPONSE_EVIDENCE"
                : "OPERATOR_SEED_WITH_NATIVE_RESPONSE_EVIDENCE",
            cells: report.scanPlan!.apiGraphql!.actors.map((actor) => {
              const c = report.apiGraphql!.checks.find((c) => c.checkId === route.id + "-observe-" + actor.id);
              return {
                actorId: actor.id,
                alias: actor.safeAlias,
                role: actor.role,
                tenantFingerprint: actor.tenantFingerprint,
                nativeOutcome: c?.outcome ?? "BLOCKED",
                nativeDecision: c?.requests[0]?.decision ?? "UNCLASSIFIED",
                statusCode: c?.requests[0]?.statusCode,
                observedMarkers: c?.observedMarkers ?? [],
                identityVerified:
                  actor.authSlot === "anonymous"
                    ? false
                    : actor.authSlot === "primary"
                      ? report.identityVerification?.primary?.verified
                      : actor.authSlot === "account_a"
                        ? report.identityVerification?.accountA?.verified
                        : report.identityVerification?.accountB?.verified
              };
            })
          }))
        : [],
      provenance:
        report && inventory && recommendations
          ? {
              observedInputs: projectAdaptiveObservedInputs(report),
              securityCases: projectAdaptiveSecurityCases(report.target, inventory, recommendations),
              attackGraph: inventory.attackGraph
            }
          : undefined,
      observationIsPolicyOrFinding: false,
      verifiedApplicationPass: false
    };
  }
  public async createMatrix(org: string, id: string, value: unknown, actor: string) {
    const policy = applicationMappingPolicySchema.parse(value),
      o = mappingObservation(this.db, org, id);
    if (!o.report || !o.scanId) throw Error("WORKBENCH_MAPPING_COMPLETE_OBSERVATION_REQUIRED");
    if (
      mappingContext(this.db, org, o.input.targetId, Object.values(o.input.credentials)).digest !== o.row.context_digest
    )
      throw Error("WORKBENCH_MAPPING_BINDINGS_CHANGED");
    return new AuthorizationWorkbenchService(this.db, this.vault, this.execution).create(
      org,
      {
        targetId: o.input.targetId,
        sourceScanId: o.scanId,
        credentials: o.input.credentials,
        mappingAcquisitionId: id,
        expectations: policy.expectations
      },
      actor
    );
  }
}
