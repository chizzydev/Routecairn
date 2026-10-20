import { applicationIdentityModel } from "../../core/auth/IdentityModel.js";
import { nativeApplicationActorMatches } from "./ApplicationIdentity.js";
import { transitionAssessmentContext } from "./ApplicationTransitionAssessment.js";
import { assertHypothesisReviewBinding } from "./ApplicationHypothesisBinding.js";
import { guidedMappingBlockers } from "./ApplicationMappingEvidence.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { randomUUID, createHash } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import type { ScanExecutionService } from "./ScanExecutionService.js";
import { TargetRepository } from "../db/DashboardRepositories.js";
import {
  authorizationWorkbenchInputSchema,
  type AuthorizationWorkbenchInput
} from "../contracts/AuthorizationWorkbenchContracts.js";
import { apiGraphqlInputSchema, type ApiGraphqlInput } from "../../modules/apiGraphql/ApiGraphqlPlanner.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { scanStudioSchema } from "../contracts/ScanStudioSchemas.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { workbenchContext } from "./AuthorizationWorkbenchBinding.js";
import { buildAdaptiveInventory, synthesizeAdaptiveRecommendations } from "./AdaptiveSynthesisCore.js";
import { projectAdaptiveSecurityCases } from "./AdaptiveSecurityCaseProjection.js";
import { synthesizeAdaptiveAuthorizationReview } from "./AdaptiveAuthorizationSynthesis.js";
import { projectAdaptiveObservedInputs } from "./AdaptiveObservedInputProjection.js";
import { compileExecutedContracts } from "./AdaptiveContractCompiler.js";
import { readFileSync } from "node:fs";
export interface AuthorizationWorkbenchResult {
  identityModels?: import("../../core/auth/IdentityModel.js").IdentityModel[];
  revisionId: string;
  version: number;
  scanId?: string | undefined;
  status: string;
  verifiedPass: boolean;
  verifiedReadOnlyChecksPass: boolean;
  hypothesisProposalId?: string | undefined;
  transitionObservation: ReturnType<typeof transitionAssessmentContext>;
  sourceHash?: string | undefined;
  checks?: NonNullable<RouteCairnReport["apiGraphql"]>["checks"] | undefined;
  findings?: RouteCairnReport["findings"] | undefined;
  requestsTransmitted?: number | undefined;
  requestAudit?:
    | {
        method: string;
        outcome: RouteCairnReport["requestAudit"][number]["outcome"];
        statusCode?: number | undefined;
      }[]
    | undefined;
  historicalGatesChanged?: false | undefined;
}
export class AuthorizationWorkbenchService {
  constructor(
    private readonly db: DashboardDatabase,
    private readonly vault: CredentialVault,
    private readonly execution: ScanExecutionService
  ) {}
  public async preview(organizationId: string, value: unknown) {
    const input = authorizationWorkbenchInputSchema.parse(value),
      context = workbenchContext(
        this.db,
        organizationId,
        input.targetId,
        input.sourceScanId,
        Object.values(input.credentials).filter((v): v is string => typeof v === "string")
      ),
      report = JSON.parse(context.reportText) as RouteCairnReport;
    if (
      report.execution?.status !== "COMPLETED" ||
      report.execution.partial ||
      new URL(report.target).origin !== context.target.base_origin ||
      !report.scanPlan?.apiGraphql ||
      !report.apiGraphql?.enabled
    )
      throw Error("WORKBENCH_COMPLETE_API_OBSERVATIONS_REQUIRED");
    const inventory = buildAdaptiveInventory(report, []),
      recommendations = synthesizeAdaptiveRecommendations(report, inventory, []),
      ir = projectAdaptiveSecurityCases(String(context.target.base_origin), inventory, recommendations),
      authorization = synthesizeAdaptiveAuthorizationReview(
        String(context.target.base_origin),
        inventory,
        recommendations
      ),
      observed = projectAdaptiveObservedInputs(report);
    assertHypothesisReviewBinding(this.db, organizationId, input);
    const source = report.scanPlan.apiGraphql,
      blockers: string[] = [],
      matrix: Array<{
        routeId: string;
        actorId: string;
        role?: string;
        tenantFingerprint?: string;
        decision: string;
        status: string;
        reason: string;
        securityCaseIds: string[];
      }> = [];
    blockers.push(...guidedMappingBlockers(this.db, organizationId, input));
    const actors: ApiGraphqlInput["actors"] = source.actors.map((a) => {
      if (a.authSlot === "anonymous")
        return { id: a.id, safeAlias: a.safeAlias, authSlot: a.authSlot, relationship: a.relationship };
      const credentialId = input.credentials[a.authSlot],
        c = credentialId ? this.vault.getSummary(credentialId, organizationId) : undefined,
        m = c?.safeIdentitySummary;
      const verification =
        a.authSlot === "primary"
          ? report.identityVerification?.primary
          : a.authSlot === "account_a"
            ? report.identityVerification?.accountA
            : report.identityVerification?.accountB;
      if (!c || !m || !nativeApplicationActorMatches(m, a, verification))
        blockers.push("ACTOR_CONTEXT_UNVERIFIED:" + a.id);
      return {
        id: a.id,
        safeAlias: a.safeAlias,
        authSlot: a.authSlot,
        relationship: a.relationship,
        ...(a.identityModel ? { identityModel: a.identityModel } : {}),
        ...(typeof m?.principalId === "string" ? { principalId: m.principalId } : {}),
        ...(typeof m?.tenantId === "string" ? { tenantId: m.tenantId } : {}),
        ...(a.role ? { role: a.role } : {})
      };
    });
    if (new Set(Object.values(input.credentials)).size !== Object.values(input.credentials).length)
      blockers.push("DISTINCT_ACTOR_CREDENTIALS_REQUIRED");
    const routes: ApiGraphqlInput["routes"] = [],
      checks: ApiGraphqlInput["checks"] = [];
    for (const [expectationIndex, e] of input.expectations.entries()) {
      if (
        actors.some((a) => "identityModel" in a && a.identityModel === "PRINCIPAL_ROLE") &&
        (e.kind === "TENANT_ISOLATION" || e.tenant)
      )
        throw Error("WORKBENCH_PRINCIPAL_ROLE_TENANT_PROOF_FORBIDDEN");
      const priorIds = input.expectations.slice(0, expectationIndex).map((v) => v.routeId);
      if (
        new Set(e.dependsOn ?? []).size !== (e.dependsOn ?? []).length ||
        (e.dependsOn ?? []).some(
          (id) =>
            !priorIds.includes(id) || input.expectations.find((v) => v.routeId === id)?.decisions.primary !== "ALLOW"
        )
      )
        throw Error("WORKBENCH_FLOW_PRIOR_ALLOW_DEPENDENCY_REQUIRED");
      const route = source.routes.find((r) => r.id === e.routeId),
        observations = report.apiGraphql.checks.filter((c) => c.routeAliases.includes(route?.safeAlias ?? ""));
      if (
        !route ||
        route.protocol !== "REST" ||
        !route.documentedMethods.includes("GET") ||
        !observations.some((o) => o.requests.length > 0)
      ) {
        blockers.push("EXACT_OBSERVED_GET_ROUTE_REQUIRED:" + e.routeId);
        continue;
      }
      if (routes.some((r) => r.id === route.id)) throw Error("WORKBENCH_DUPLICATE_OPERATION");
      const { path, ...originalRoute } = route;
      const boundUrl = e.url ? new URL(e.url) : undefined;
      const templateSegments = path.split("/"),
        urlSegments = boundUrl?.pathname.split("/") ?? [];
      if (
        !boundUrl ||
        boundUrl.origin !== context.target.base_origin ||
        boundUrl.username ||
        boundUrl.password ||
        boundUrl.search ||
        boundUrl.hash ||
        boundUrl.pathname.includes("%") ||
        templateSegments.length !== urlSegments.length ||
        templateSegments.some((v, i) =>
          v.startsWith(":") ? !/^[A-Za-z0-9._-]{1,80}$/.test(urlSegments[i] ?? "") : v !== urlSegments[i]
        )
      ) {
        blockers.push("EXACT_OBSERVED_TEMPLATE_URL_BINDING_REQUIRED:" + e.routeId);
        continue;
      }
      routes.push({
        id: route.id,
        safeAlias: route.safeAlias,
        protocol: "REST",
        kind: route.kind,
        url: boundUrl.href,
        pathTemplate: path,
        objectType: route.objectType,
        functionName: route.functionName,
        documented: true,
        documentedMethods: ["GET"],
        documentedResponseFields: [],
        operatorConfirmedNonMutatingPost: false
      });
      void originalRoute;
      const fingerprints = source.checks
        .filter((c) => "routeId" in c && c.routeId === route.id)
        .map((c) => c.comparisonFingerprint);
      const caseIds = ir.cases
        .filter(
          (c) =>
            c.source.engineId === "api-graphql-authorization" &&
            (c.subject.kind === "ROUTE"
              ? c.subject.pathTemplate === path
              : c.provenance.sourceCaseFingerprints?.some((fp) => fingerprints.includes(fp)) ||
                c.provenance.graph?.pathIds.some((id) =>
                  inventory.attackGraph?.paths
                    .find((p) => p.id === id)
                    ?.sourceCaseFingerprints.some((fp) => fingerprints.includes(fp))
                ))
        )
        .map((c) => c.caseId);
      if (!caseIds.length) blockers.push("SECURITY_CASE_PROVENANCE_REQUIRED:" + e.routeId);
      if (!e.identity) blockers.push("EXACT_OBJECT_OR_FUNCTION_MARKER_REQUIRED:" + e.routeId);
      if (e.kind === "TENANT_ISOLATION" && !e.tenant) blockers.push("EXACT_TENANT_REQUIRED:" + e.routeId);
      const decisions = Object.values(e.decisions);
      if (!decisions.includes("ALLOW") || !decisions.includes("DENY"))
        blockers.push("ALLOW_DENY_CONTROL_PAIR_REQUIRED:" + e.routeId);
      for (const key of Object.keys(e.decisions))
        if (!actors.some((a) => a.id === key)) throw Error("WORKBENCH_UNKNOWN_ACTOR");
      for (const actor of actors) {
        const decision = e.decisions[actor.id] ?? "UNKNOWN",
          status = decision === "UNKNOWN" || !e.identity || !caseIds.length ? "REQUIRES_BINDINGS" : "READY_READ_ONLY";
        matrix.push({
          routeId: e.routeId,
          actorId: actor.id,
          ...(actor.role ? { role: actor.role } : {}),
          ...(source.actors.find((a) => a.id === actor.id)?.tenantFingerprint
            ? { tenantFingerprint: source.actors.find((a) => a.id === actor.id)!.tenantFingerprint }
            : {}),
          decision,
          status,
          reason: e.explanation,
          securityCaseIds: caseIds
        });
        if (status === "REQUIRES_BINDINGS")
          blockers.push("EXPECTED_DECISION_OR_PROOF_REQUIRED:" + e.routeId + ":" + actor.id);
        if (decision !== "UNKNOWN")
          checks.push({
            id: e.routeId + "-" + actor.id,
            matrixId: e.routeId,
            label: e.explanation,
            kind: e.kind,
            routeId: route.id,
            actorId: actor.id,
            requireVerifiedIdentity: true,
            ...(e.dependsOn?.length
              ? {
                  prerequisiteCheckIds: [
                    ...new Set(
                      e.dependsOn.flatMap((id) => [
                        id + "-primary",
                        ...(actor.id !== "primary" &&
                        input.expectations.find((v) => v.routeId === id)?.decisions[actor.id] === "ALLOW"
                          ? [id + "-" + actor.id]
                          : [])
                      ])
                    )
                  ]
                }
              : {}),
            request: { method: "GET", headers: {}, operatorConfirmedNonMutating: false },
            response: {
              expectedDecision: decision,
              allowedStatuses: [200],
              deniedStatuses: [401, 403, 404],
              fieldRules: [],
              ...(e.states ? { stateMarkers: e.states } : {}),
              ...(e.identity ? { identity: e.identity } : {}),
              ...(e.tenant ? { tenant: { ...e.tenant, forbiddenValues: [] } } : {})
            }
          });
      }
    }
    const apiGraphql =
        routes.length && checks.length
          ? apiGraphqlInputSchema.parse({
              schemaVersion: 1,
              maxRequests: 32,
              maxResponseBytes: 8192,
              actors,
              routes,
              checks
            })
          : undefined,
      target = new TargetRepository(this.db).get(input.targetId)!;
    const request: DashboardScanCreateRequest = {
      target: target.baseOrigin,
      targetId: target.id,
      ...(target.projectId ? { projectId: target.projectId } : {}),
      profile: "quick",
      includeModules: ["api-graphql-authorization"],
      maxRequests: 40,
      cleanupReservedRequests: 0,
      rateLimitPerSecond: Math.min(20, Number(target.approvedScope.rateLimitPerSecond)),
      concurrency: 1,
      authorizationDeclaration: "Explicitly reviewed owned loopback read-only authorization matrix",
      apiGraphql,
      studio: scanStudioSchema.parse({
        version: 1,
        scanName: "Application authorization workbench",
        authorization: { category: "OWNED", confirmed: true },
        scope: target.approvedScope,
        authentication: { mode: "public" }
      }),
      ...(input.credentials.primary ? { credentialProfileId: input.credentials.primary } : {}),
      ...(input.credentials.account_a ? { credentialProfileAId: input.credentials.account_a } : {}),
      ...(input.credentials.account_b ? { credentialProfileBId: input.credentials.account_b } : {})
    };
    const matcher = new ScopeMatcher(target.baseOrigin, scopeSchema.parse(target.approvedScope));
    const transportIntents: Array<{
      purpose: string;
      actorId: string;
      method: "GET";
      url: string;
      credentialProfileId?: string;
    }> = [{ purpose: "CORE_BASELINE", actorId: "anonymous", method: "GET", url: new URL("/", target.baseOrigin).href }];
    for (const actor of actors) {
      if (actor.authSlot === "anonymous") continue;
      const credentialProfileId = input.credentials[actor.authSlot];
      if (!credentialProfileId) continue;
      const identity = this.vault.decryptForHealthCheck(credentialProfileId).identityVerification;
      let endpoint: URL | undefined;
      try {
        endpoint = identity ? new URL(identity.endpoint, target.baseOrigin) : undefined;
      } catch {
        /* Binding remains unresolved. */
      }
      if (
        !endpoint ||
        endpoint.origin !== target.baseOrigin ||
        endpoint.username ||
        endpoint.password ||
        endpoint.search ||
        endpoint.hash ||
        !identity?.roleFieldPath ||
        (actor.identityModel !== "PRINCIPAL_ROLE"
          ? !identity.tenantFieldPath
          : !!identity.tenantFieldPath || !identity.principalFieldPath) ||
        !matcher.decide(endpoint.href, "GET").allowed
      ) {
        blockers.push("EXACT_SCOPED_IDENTITY_CONTRACT_REQUIRED:" + actor.id);
        continue;
      }
      transportIntents.push({
        purpose: "VERIFY_PRINCIPAL_TENANT_ROLE",
        actorId: actor.id,
        method: "GET",
        url: endpoint.href,
        credentialProfileId
      });
    }
    for (const check of checks) {
      if ("routeId" in check) {
        const route = routes.find((r) => r.id === check.routeId);
        if (route) transportIntents.push({ purpose: check.id, actorId: check.actorId, method: "GET", url: route.url });
      }
    }
    if (blockers.length) for (const cell of matrix) cell.status = "REQUIRES_BINDINGS";
    const runtimePreview = blockers.length ? undefined : await this.execution.preview(request);
    if (runtimePreview && !runtimePreview.credentialReadiness.ready) blockers.push("CREDENTIAL_READINESS_BLOCKED");
    const digest = adaptiveDigest({
      input,
      contextDigest: context.digest,
      request,
      previewIdentity: runtimePreview?.previewIdentity ?? null
    });
    return {
      schemaVersion: 1 as const,
      input,
      digest,
      contextDigest: context.digest,
      sourceHash: context.sourceHash,
      matrix,
      blockers: [...new Set(blockers)],
      classification: blockers.length ? "REQUIRES_BINDINGS" : "READY_READ_ONLY",
      request,
      preview: runtimePreview,
      transportIntents,
      proofBudget: {
        checks: checks.length,
        identityRequests: actors.filter((a) => a.authSlot !== "anonymous").length,
        totalRequestCeiling: 40,
        perEngineCeiling: 32,
        maxResponseBytes: 8192
      },
      provenance: {
        observations: observed,
        securityCases: ir,
        authorizationReview: authorization,
        attackGraph: inventory.attackGraph,
        executedContracts: compileExecutedContracts(report).map((c) => ({
          engineId: c.engineId,
          evidenceFingerprint: c.evidenceFingerprint,
          requestCount: c.requestCount
        }))
      },
      executionAuthority: "EXPLICIT_REVIEW_REQUIRED",
      trustedDiscoveryExecution: false
    };
  }
  public async create(org: string, value: unknown, actor: string) {
    const preview = await this.preview(org, value);
    assertHypothesisReviewBinding(this.db, org, preview.input, actor);
    const id = randomUUID(),
      now = new Date().toISOString(),
      expires = new Date(Date.now() + 600000).toISOString();
    this.db.db
      .transaction(() => {
        const version = (
          this.db.db
            .prepare("SELECT COALESCE(MAX(version),0)+1 n FROM authorization_workbench_revisions WHERE target_id=?")
            .get(preview.input.targetId) as { n: number }
        ).n;
        this.db.db
          .prepare("INSERT INTO authorization_workbench_revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
          .run(
            id,
            org,
            preview.input.targetId,
            version,
            preview.input.sourceScanId,
            JSON.stringify(preview.input),
            JSON.stringify(preview.request),
            preview.contextDigest,
            preview.digest,
            preview.preview?.previewIdentity ?? "",
            actor,
            now,
            expires,
            JSON.stringify(preview)
          );
      })
      .immediate();
    return { revisionId: id, expiresAt: expires, ...preview };
  }
  public row(org: string, id: string) {
    const r = this.db.db
      .prepare("SELECT * FROM authorization_workbench_revisions WHERE id=? AND organization_id=?")
      .get(id, org) as Record<string, string> | undefined;
    if (!r) throw Error("WORKBENCH_REVISION_NOT_FOUND");
    return r;
  }
  public async execute(org: string, id: string, digest: string, actor: string) {
    const row = this.row(org, id);
    if (row.digest !== digest) throw Error("WORKBENCH_STALE_REVIEW");
    const prior = this.db.db
      .prepare(
        "SELECT d.requested_by,a.scan_id FROM authorization_workbench_dispatches d LEFT JOIN authorization_workbench_acknowledgements a ON a.revision_id=d.revision_id WHERE d.revision_id=?"
      )
      .get(id) as { requested_by: string; scan_id: string | null } | undefined;
    if (prior) {
      if (prior.requested_by !== actor) throw Error("WORKBENCH_CONSUMED_BY_ANOTHER_OPERATOR");
      return { scanId: prior.scan_id, status: prior.scan_id ? "ALREADY_RECORDED" : "UNKNOWN", replayed: false };
    }
    if (!Number.isFinite(Date.parse(row.expires_at!)) || Date.parse(row.expires_at!) <= Date.now())
      throw Error("WORKBENCH_STALE_REVIEW");
    const fresh = await this.preview(org, JSON.parse(row.input_json!));
    if (fresh.digest !== digest || fresh.blockers.length) throw Error("WORKBENCH_BINDINGS_CHANGED");
    this.db.db
      .prepare("INSERT INTO authorization_workbench_dispatches VALUES(?,?,?)")
      .run(id, actor, new Date().toISOString());
    const request = JSON.parse(row.request_json!) as DashboardScanCreateRequest;
    request.authorizationWorkbenchBinding = { revisionId: id, digest };
    const scanId = await this.execution.enqueue(request, undefined, undefined, org);
    this.db.db
      .prepare("INSERT INTO authorization_workbench_acknowledgements VALUES(?,?,?)")
      .run(id, scanId, new Date().toISOString());
    return { scanId, status: "QUEUED", replayed: false };
  }
  public result(org: string, id: string): AuthorizationWorkbenchResult {
    const row = this.row(org, id),
      ack = this.db.db
        .prepare("SELECT scan_id FROM authorization_workbench_acknowledgements WHERE revision_id=?")
        .get(id) as { scan_id: string } | undefined;
    const transitionObservation = transitionAssessmentContext(this.db, org, JSON.parse(row.input_json!));
    const reviewId = (JSON.parse(row.input_json!) as AuthorizationWorkbenchInput).hypothesisReviewId,
      hypothesisProposalId = reviewId
        ? (
            this.db.db
              .prepare(
                "SELECT d.proposal_id FROM application_hypothesis_decisions d JOIN application_hypothesis_proposals p ON p.id=d.proposal_id WHERE d.id=? AND p.organization_id=?"
              )
              .get(reviewId, org) as { proposal_id: string } | undefined
          )?.proposal_id
        : undefined;
    const scan = ack
      ? (this.db.db
          .prepare("SELECT id,status,error_summary FROM scans WHERE id=? AND organization_id=?")
          .get(ack.scan_id, org) as { id: string; status: string; error_summary: string | null } | undefined)
      : undefined;
    if (!scan || scan.status !== "COMPLETED")
      return {
        revisionId: id,
        version: Number(row.version),
        scanId: scan?.id,
        status:
          scan?.status ??
          (this.db.db.prepare("SELECT 1 FROM authorization_workbench_dispatches WHERE revision_id=?").get(id)
            ? "UNKNOWN"
            : "REVIEW_REQUIRED"),
        ...(hypothesisProposalId ? { hypothesisProposalId } : {}),
        verifiedPass: false,
        verifiedReadOnlyChecksPass: false,
        identityModels: [
          ...new Set<ReturnType<typeof applicationIdentityModel>>(
            (JSON.parse(row.request_json!).apiGraphql?.actors ?? [])
              .filter((a: { authSlot: string }) => a.authSlot !== "anonymous")
              .map((a: { identityModel?: unknown }) => applicationIdentityModel(a.identityModel))
          )
        ],
        transitionObservation
      };
    const artifact = this.db.db
      .prepare(
        "SELECT a.canonical_path,a.scoped_or_full_safe_hash FROM scans s JOIN artifacts a ON a.id=s.json_report_artifact_id WHERE s.id=? AND s.organization_id=?"
      )
      .get(scan.id, org) as { canonical_path: string; scoped_or_full_safe_hash: string };
    const bytes = readFileSync(artifact.canonical_path);
    if (createHash("sha256").update(bytes).digest("hex") !== artifact.scoped_or_full_safe_hash)
      throw Error("WORKBENCH_RESULT_CHANGED");
    const report = JSON.parse(bytes.toString()) as RouteCairnReport,
      r = report.apiGraphql;
    const expected = JSON.parse(row.request_json!)
        .apiGraphql.checks.map((c: { id: string }) => c.id)
        .sort(),
      native = r?.checks.map((c) => c.checkId).sort() ?? [],
      plan = report.scanPlan?.apiGraphql?.checks.map((c) => c.id).sort() ?? [];
    if (
      new Set(native).size !== native.length ||
      new Set(expected).size !== expected.length ||
      JSON.stringify(expected) !== JSON.stringify(native) ||
      JSON.stringify(expected) !== JSON.stringify(plan)
    )
      throw Error("WORKBENCH_RESULT_INCOMPLETE");
    if (
      !r ||
      r.checks.length !== JSON.parse(row.request_json!).apiGraphql.checks.length ||
      r.plannedChecks !== r.checks.length ||
      report.execution?.status !== "COMPLETED" ||
      report.execution.partial
    )
      throw Error("WORKBENCH_RESULT_INCOMPLETE");
    return {
      revisionId: id,
      version: Number(row.version),
      scanId: scan.id,
      ...(hypothesisProposalId ? { hypothesisProposalId } : {}),
      status: r.failedChecks
        ? "FINDINGS"
        : r.inconclusiveChecks || r.blockedChecks || transitionObservation
          ? "INCONCLUSIVE"
          : "PASS",
      verifiedPass: !transitionObservation && r.passedChecks === r.plannedChecks && r.plannedChecks > 0,
      verifiedReadOnlyChecksPass: r.passedChecks === r.plannedChecks && r.plannedChecks > 0,
      transitionObservation,
      identityModels: [
        ...new Set<ReturnType<typeof applicationIdentityModel>>(
          report.scanPlan?.apiGraphql?.actors
            .filter((a) => a.authSlot !== "anonymous")
            .map((a) => applicationIdentityModel(a.identityModel))
        )
      ],
      checks: r.checks,
      requestsTransmitted: r.requestsTransmitted,
      requestAudit: report.requestAudit.map((a) => ({
        method: a.method,
        outcome: a.outcome,
        statusCode: a.statusCode
      })),
      sourceHash: createHash("sha256").update(bytes).digest("hex"),
      findings: report.findings.filter((f) => f.sourceModule === "api-graphql-authorization"),
      historicalGatesChanged: false
    };
  }
}
