import { createHash } from "node:crypto";
import { join } from "node:path";
import { durableAtomicWrite } from "../offensive/MutationJournal.js";
import { readMutationCleanupStatus } from "../offensive/MutationCleanupStatus.js";
import { workflowKeys } from "../offensive/WorkflowMutationCoordinator.js";
import { acceptAssistedWorkflowFindings } from "../findings/AssistedWorkflowFindingAcceptance.js";
import { ScanContext, type ScanContextOptions } from "./ScanContext.js";
import { ScanOrchestrator } from "./ScanOrchestrator.js";
import { JsonReportWriter } from "../../reports/JsonReportWriter.js";
import { MarkdownReportWriter } from "../../reports/MarkdownReportWriter.js";
import { HtmlReportWriter } from "../../reports/HtmlReportWriter.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { legacyModeForProfile, profileSummary } from "../../config/ScanProfiles.js";
import { verifyScanIdentities } from "../auth/IdentityVerification.js";
import { ScanCancelledError } from "./ScanEvents.js";
import { verifyPreHandoverSetup } from "../../modules/preHandover/PreHandoverRuntime.js";

export interface ScanResult {
  status: "COMPLETED" | "CANCELLED" | "FAILED";
  reportPath: string;
  markdownReportPath: string;
  htmlReportPath: string;
}

export class RouteCairnEngine {
  private readonly orchestrator = new ScanOrchestrator();
  private readonly jsonReportWriter = new JsonReportWriter();
  private readonly markdownReportWriter = new MarkdownReportWriter();
  private readonly htmlReportWriter = new HtmlReportWriter();

  public async scan(options: ScanContextOptions): Promise<ScanResult> {
    const deadlineController = new AbortController();
    let deadlineExceeded = false;
    const deadlineTimer = setTimeout(() => { deadlineExceeded = true; deadlineController.abort(); }, options.plan.limits.maxScanDurationMs);
    const effectiveAbortSignal = options.abortSignal ? AbortSignal.any([options.abortSignal, deadlineController.signal]) : deadlineController.signal;
    let status: NonNullable<RouteCairnReport["execution"]>["status"] = "RUNNING";
    let reason = "Execution is incomplete; missing coverage is not a security pass.";
    let checkpointQueue = Promise.resolve();
    const context = new ScanContext({ ...options, abortSignal: effectiveAbortSignal, checkpointReport: () => checkpoint() });

    const makeReport = async (): Promise<RouteCairnReport> => {
      const partialResults = [...context.partialModules.values()].map((snapshot) => {
        const raw = snapshot();
        try { return acceptAssistedWorkflowFindings(raw); }
        catch { return { ...raw, findings: [] }; }
      });
      const stateReport = context.state.toReport(options.plan);
      for (const result of partialResults) {
        for (const key of workflowKeys) if (result[key]) Object.assign(stateReport, { [key]: result[key] });
        stateReport.findings.push(...(result.findings ?? []));
      }
      let cleanup: NonNullable<RouteCairnReport["execution"]>["cleanup"];
      try {
        const pending = await readMutationCleanupStatus(context.mutations.directory, join(context.mutations.directory, "mutation-journals.json"));
        // Global obligations are deliberately retained: they block this scan's
        // subsequent mutation workflows even when another job created them.
        cleanup = { state: pending.cases.length ? "REQUIRED" : "CLEAR", cases: pending.cases.map(({ caseId, stage, recoveryBundleAvailable }) => ({ caseId, stage, recoveryBundleAvailable })) };
      } catch { cleanup = { state: "UNKNOWN", cases: [] }; }
      return {
        routeCairnVersion: "0.1.0", target: options.target,
        mode: options.plan.metadata.legacyMode ?? legacyModeForProfile(options.plan.profile),
        profile: profileSummary(options.plan), scanPlan: safePlanForReport(options.plan), program: options.scope.program,
        scope: {
          allowedDomains: options.scope.allowedDomains, disallowedPaths: options.scope.disallowedPaths,
          allowedMethods: options.scope.allowedMethods, rateLimitPerSecond: options.plan.limits.rateLimitPerSecond,
          concurrency: options.plan.limits.concurrency, sameOriginOnly: options.scope.sameOriginOnly, includeSubdomains: options.scope.includeSubdomains
        },
        ...safeStateReportForReport(stateReport, options.plan),
        execution: { status, partial: status !== "COMPLETED", reason, checkpointAt: new Date().toISOString(), cleanup }
      };
    };
    const checkpoint = (): Promise<void> => {
      checkpointQueue = checkpointQueue.then(async () => {
        const report = await makeReport();
        await durableAtomicWrite(join(options.outputDir, "report.partial.json"), JSON.stringify(report));
      }).catch(async () => {
        // Report I/O must never prevent restoration. Encrypted mutation intent
        // and recovery material have their own fail-closed durability boundary.
        await options.eventSink?.emit({ type: "OBSERVATION_RECORDED", message: "Partial report checkpoint could not be written; recovery obligations remain independent.", metadata: { category: "PARTIAL_REPORT_WRITE_FAILED" } });
      });
      return checkpointQueue;
    };
    try {
      await checkpoint();
      const identityVerification = await verifyScanIdentities(context);
      if (identityVerification) context.state.recordIdentityVerification(identityVerification);
      await verifyPreHandoverSetup(context);
      await this.orchestrator.run(context);
      status = "COMPLETED";
      reason = "Planned execution completed.";
    } catch (error) {
      context.state.complete();
      status = error instanceof ScanCancelledError || effectiveAbortSignal.aborted ? "CANCELLED" : "FAILED";
      reason = status === "CANCELLED"
        ? deadlineExceeded ? "Scan duration limit reached; remaining coverage was not assessed." : "Operator cancelled execution; remaining coverage was not assessed."
        : "Execution failed; only evidence collected before the failure is included.";
      await options.eventSink?.emit({ type: status === "CANCELLED" ? "SCAN_CANCELLED" : "SCAN_FAILED", message: reason });
    } finally {
      clearTimeout(deadlineTimer);
      context.dispose();
    }
    await checkpoint();
    const report = await makeReport();
    const reportPath = await this.jsonReportWriter.write(options.outputDir, report);
    const markdownReportPath = await this.markdownReportWriter.write(options.outputDir, report);
    const htmlReportPath = await this.htmlReportWriter.write(options.outputDir, report);
    await options.eventSink?.emit({ type: "REPORT_WRITTEN", message: report.execution?.partial ? "Partial reports written." : "Reports written.", metadata: { reportPath, markdownReportPath, htmlReportPath, partial: report.execution?.partial } });
    return { status, reportPath, markdownReportPath, htmlReportPath };
  }
}
function safeStateReportForReport<T extends ReturnType<ScanContext["state"]["toReport"]>>(stateReport: T, plan: ScanContextOptions["plan"]): T {
  if (!plan.objectPairTesting && !plan.fieldExposureTesting && !plan.authorizationMatrixTesting && !plan.collectionAuthorizationTesting && !plan.bulkAuthorizationTesting && !plan.fileAuthorizationTesting && !plan.equivalentRouteTesting && !plan.supabaseAuthorization && !plan.apiGraphql && !plan.linkPortalSecurity && !plan.operationalEndpointSecurity && !plan.billingEntitlement) {
    return stateReport;
  }

  const objectIds = objectIdRedactionPairs(plan);
  const apiRoutes = apiRouteRedactionPairs(plan);
  return {
    ...stateReport,
    requestAudit: stateReport.requestAudit.map((entry) => ({
      ...entry,
      requestedUrl: redactApiRoutes(redactSupabaseQuery(redactObjectIds(entry.requestedUrl, objectIds), Boolean(plan.supabaseAuthorization)), apiRoutes),
      ...(entry.finalUrl ? { finalUrl: redactApiRoutes(redactSupabaseQuery(redactObjectIds(entry.finalUrl, objectIds), Boolean(plan.supabaseAuthorization)), apiRoutes) } : {}),
      redirectChain: entry.redirectChain.map((hop) => ({ ...hop, location: redactApiRoutes(redactSupabaseQuery(redactObjectIds(hop.location, objectIds), Boolean(plan.supabaseAuthorization)), apiRoutes) }))
    }))
  };
}

function safePlanForReport(plan: ScanContextOptions["plan"]): ScanContextOptions["plan"] {
  if (!plan.objectPairTesting && !plan.fieldExposureTesting && !plan.authorizationMatrixTesting && !plan.collectionAuthorizationTesting && !plan.bulkAuthorizationTesting && !plan.fileAuthorizationTesting && !plan.equivalentRouteTesting && !plan.supabaseAuthorization && !plan.apiGraphql && !plan.linkPortalSecurity && !plan.operationalEndpointSecurity && !plan.billingEntitlement && !plan.privilegeMutationTesting) {
    return plan;
  }

  const objectIds = objectIdRedactionPairs(plan);

  const redactAssertions = <T extends { expectedValue?: unknown }>(assertions: readonly T[]): T[] => assertions.map((assertion) => ({ ...assertion, ...(Object.hasOwn(assertion, "expectedValue") ? { expectedValue: "<redacted>" } : {}) }));

  return {
    ...plan,
    ...(plan.privilegeMutationTesting ? { privilegeMutationTesting: {
      ...plan.privilegeMutationTesting,
      cases: plan.privilegeMutationTesting.cases.map((item) => ({
        ...item,
        target: { ...item.target, identityAssertions: redactAssertions(item.target.identityAssertions) },
        originalAuthority: { ...item.originalAuthority, assertions: redactAssertions(item.originalAuthority.assertions) },
        impact: { ...item.impact, assertions: redactAssertions(item.impact.assertions) },
        rollback: { ...item.rollback, verification: { ...item.rollback.verification, assertions: redactAssertions(item.rollback.verification.assertions) } }
      }))
    } } : {}),
    ...(plan.objectPairTesting
      ? {
          objectPairTesting: {
            ...plan.objectPairTesting,
            cases: plan.objectPairTesting.cases.map((testCase) => ({
              ...testCase,
              template: { ...testCase.template, urlTemplate: redactObjectIds(testCase.template.urlTemplate, objectIds) },
              accountAObject: redactObjectPairAssertion(testCase.accountAObject),
              accountBObject: redactObjectPairAssertion(testCase.accountBObject),
              requestMatrix: testCase.requestMatrix.map((request) => ({
                ...request,
                targetObjectId: "<redacted>",
                url: redactObjectIds(request.url, objectIds)
              }))
            })),
            requestMatrix: plan.objectPairTesting.requestMatrix.map((request) => ({
              ...request,
              targetObjectId: "<redacted>",
              url: redactObjectIds(request.url, objectIds)
            }))
          }
        }
      : {}),
    ...(plan.fieldExposureTesting
      ? {
          fieldExposureTesting: {
            ...plan.fieldExposureTesting,
            cases: plan.fieldExposureTesting.cases.map((testCase) => ({
              ...testCase,
              objectId: "<redacted>",
              template: { ...testCase.template, urlTemplate: redactObjectIds(testCase.template.urlTemplate, objectIds) },
              objectConfirmation: redactFieldExposureObjectConfirmation(testCase.objectConfirmation),
              fieldExpectations: testCase.fieldExpectations.map(redactFieldExpectation),
              requestMatrix: testCase.requestMatrix.map((request) => ({ ...request, url: redactObjectIds(request.url, objectIds) }))
            })),
            requestMatrix: plan.fieldExposureTesting.requestMatrix.map((request) => ({ ...request, url: redactObjectIds(request.url, objectIds) }))
          }
        }
      : {}),
    ...(plan.authorizationMatrixTesting
      ? {
          authorizationMatrixTesting: {
            ...plan.authorizationMatrixTesting,
            matrices: plan.authorizationMatrixTesting.matrices.map((matrix) => ({
              ...matrix,
              template: { ...matrix.template, urlTemplate: redactObjectIds(matrix.template.urlTemplate, objectIds) },
              cases: matrix.cases.map(redactAuthorizationMatrixCase)
            })),
            requestMatrix: plan.authorizationMatrixTesting.requestMatrix.map(redactAuthorizationMatrixCase)
          }
        }
      : {}),
    ...(plan.collectionAuthorizationTesting
      ? {
          collectionAuthorizationTesting: {
            ...plan.collectionAuthorizationTesting,
            collections: plan.collectionAuthorizationTesting.collections.map((collection) => ({
              ...collection,
              url: redactObjectIds(collection.url, objectIds),
              knownObjects: collection.knownObjects.map(redactKnownCollectionObject),
              cases: collection.cases.map(redactCollectionAuthorizationCase)
            })),
            requestMatrix: plan.collectionAuthorizationTesting.requestMatrix.map(redactCollectionAuthorizationCase)
          }
        }
      : {}),
	    ...(plan.bulkAuthorizationTesting
      ? {
          bulkAuthorizationTesting: {
            ...plan.bulkAuthorizationTesting,
            definitions: plan.bulkAuthorizationTesting.definitions.map((definition) => ({
              ...definition,
              cases: definition.cases.map(redactBulkAuthorizationCase)
            })),
            requestMatrix: plan.bulkAuthorizationTesting.requestMatrix.map(redactBulkAuthorizationCase)
          }
        }
	      : {}),
    ...(plan.fileAuthorizationTesting
      ? {
          fileAuthorizationTesting: {
            ...plan.fileAuthorizationTesting,
            definitions: plan.fileAuthorizationTesting.definitions.map((definition) => ({
              ...definition,
              files: definition.files.map((file) => ({ ...file, fileRef: "<redacted>" })),
              cases: definition.cases.map(redactFileAuthorizationCase)
            })),
            requestMatrix: plan.fileAuthorizationTesting.requestMatrix.map(redactFileAuthorizationCase)
          }
        }
      : {}),
    ...(plan.equivalentRouteTesting
      ? {
          equivalentRouteTesting: {
            ...plan.equivalentRouteTesting,
            routeSets: plan.equivalentRouteTesting.routeSets.map((routeSet) => ({
              ...routeSet,
              objectId: "<redacted>",
              ...(routeSet.expectedObjectState ? { expectedObjectState: `<state:${hashValue(routeSet.expectedObjectState)}>` } : {}),
              routes: routeSet.routes.map((route) => ({ ...route, template: { ...route.template, urlTemplate: redactObjectIds(route.template.urlTemplate, objectIds) } })),
              cells: routeSet.cells.map(redactEquivalentRouteCell)
            })),
            requestMatrix: plan.equivalentRouteTesting.requestMatrix.map(redactEquivalentRouteCell)
          }
        }
      : {}),
    ...(plan.supabaseAuthorization
      ? {
          supabaseAuthorization: {
            ...plan.supabaseAuthorization,
            cases: plan.supabaseAuthorization.cases.map((testCase) => ({
              ...testCase,
              url: redactSupabaseQuery(redactObjectIds(testCase.url, objectIds), true),
              identityAssertions: testCase.identityAssertions.map((assertion) => ({ ...assertion, expectedValue: "<redacted>" })),
              ...(testCase.signedUrl?.expectedPathContains ? { signedUrl: { ...testCase.signedUrl, expectedPathContains: "<redacted>" } } : {})
            }))
          }
        }
      : {})
    ,...(plan.apiGraphql ? { apiGraphql: redactApiGraphqlPlan(plan.apiGraphql) } : {}),
    ...(plan.linkPortalSecurity ? { linkPortalSecurity: redactLinkPortalPlan(plan.linkPortalSecurity) } : {}),
    ...(plan.operationalEndpointSecurity ? { operationalEndpointSecurity: redactOperationalEndpointPlan(plan.operationalEndpointSecurity) } : {}),
    ...(plan.billingEntitlement ? { billingEntitlement: redactBillingEntitlementPlan(plan.billingEntitlement) } : {})
  };
}

function redactBillingEntitlementPlan(plan: NonNullable<ScanContextOptions["plan"]["billingEntitlement"]>): NonNullable<ScanContextOptions["plan"]["billingEntitlement"]> {
  const endpoints = new Map(plan.endpoints.map((endpoint) => [endpoint.id, endpoint.safeAlias]));
  return { ...plan, provider: { ...plan.provider, fixturePathPrefix: "<redacted-fixture-path>" }, cases: plan.cases.map((testCase) => ({ ...testCase, steps: testCase.steps.map((step) => ({ ...step, request: { ...step.request, urlTemplate: `redacted://${endpoints.get(step.endpointId) ?? "endpoint"}`, headers: {}, ...(step.request.fields !== undefined ? { fields: "<redacted>" } : {}), ...(step.request.hmac ? { hmac: { ...step.request.hmac, secretRef: "<redacted-ref>", ...(step.request.hmac.timestampSecretRef ? { timestampSecretRef: "<redacted-ref>" } : {}) } } : {}) } })), assertions: testCase.assertions.map((assertion) => assertion.kind === "VALUE_EQUALS_SECRET" || assertion.kind === "VALUE_NOT_EQUALS_SECRET" ? { ...assertion, secretRef: "<redacted-ref>" } : assertion) })) };
}

function redactOperationalEndpointPlan(plan: NonNullable<ScanContextOptions["plan"]["operationalEndpointSecurity"]>): NonNullable<ScanContextOptions["plan"]["operationalEndpointSecurity"]> {
  const endpoints = new Map(plan.endpoints.map((endpoint) => [endpoint.id, endpoint.safeAlias]));
  return { ...plan, cases: plan.cases.map((testCase) => ({ ...testCase, steps: testCase.steps.map((step) => ({ ...step, request: { ...step.request, urlTemplate: `redacted://${endpoints.get(step.endpointId) ?? "endpoint"}`, headers: {}, ...(step.request.fields !== undefined ? { fields: "<redacted>" } : {}), ...(step.request.hmac ? { hmac: { ...step.request.hmac, secretRef: "<redacted-ref>", ...(step.request.hmac.timestampSecretRef ? { timestampSecretRef: "<redacted-ref>" } : {}) } } : {}) }, assertions: step.assertions.map((assertion) => assertion.kind === "JSON_EQUALS_SECRET" || assertion.kind === "CAPTURE_EQUALS_SECRET" || assertion.kind === "CAPTURE_NOT_EQUALS_SECRET" ? { ...assertion, secretRef: "<redacted-ref>" } : assertion) })) })) };
}

function redactLinkPortalPlan(plan: NonNullable<ScanContextOptions["plan"]["linkPortalSecurity"]>): NonNullable<ScanContextOptions["plan"]["linkPortalSecurity"]> {
  const resources = new Map(plan.resources.map((resource) => [resource.id, resource.safeAlias]));
  return {
    ...plan,
    cases: plan.cases.map((testCase) => ({
      ...testCase,
      steps: testCase.steps.map((step) => ({
        ...step,
        request: {
          ...step.request,
          urlTemplate: `redacted://${resources.get(step.resourceId) ?? "resource"}`,
          headers: {},
          ...(step.request.fields ? { fields: { redacted: "<redacted>" } } : {})
        }
      }))
    }))
  };
}

function redactApiGraphqlPlan(plan: NonNullable<ScanContextOptions["plan"]["apiGraphql"]>): NonNullable<ScanContextOptions["plan"]["apiGraphql"]> {
  const redactRequest = <T extends { body?: unknown; graphql?: { variables: Readonly<Record<string, unknown>> } }>(request: T): T => ({
    ...request,
    ...(request.body !== undefined ? { body: "<redacted>" } : {}),
    ...(request.graphql ? { graphql: { ...request.graphql, document: `<redacted-query:${hashValue((request.graphql as { document?: string }).document ?? "")}>`, variables: {} } } : {})
  });
  return {
    ...plan,
    routes: plan.routes.map((route) => ({ ...route, url: `redacted://${route.safeAlias}` })),
    checks: plan.checks.map((check) => {
      if (check.kind === "GRAPHQL_INTROSPECTION") return check;
      if (check.kind === "GRAPHQL_ALIAS_LIMIT" || check.kind === "GRAPHQL_BATCH_LIMIT") return { ...check, documents: check.documents.map((operation) => ({ ...operation, document: `<redacted-query:${hashValue(operation.document)}>`, variables: {} })) };
      if (check.kind === "METHOD_CONFUSION") return { ...check, request: redactRequest(check.request) };
      if (check.kind === "VERSION_BOUNDARY") return { ...check, request: redactRequest(check.request) };
      if (!("request" in check) || !("response" in check)) return check;
      return {
        ...check,
        request: redactRequest(check.request),
        response: {
          ...check.response,
          ...(check.response.identity ? { identity: { ...check.response.identity, expectedValue: "<redacted>" } } : {}),
          ...(check.response.tenant ? { tenant: { ...check.response.tenant, ...(check.response.tenant.expectedValue !== undefined ? { expectedValue: "<redacted>" } : {}), forbiddenValues: [] } } : {})
        }
      };
    })
  };
}

function apiRouteRedactionPairs(plan: ScanContextOptions["plan"]): Array<{ url: string; alias: string }> { return plan.apiGraphql?.routes.map((route) => ({ url: route.url, alias: route.safeAlias })) ?? []; }
function redactApiRoutes(value: string, routes: readonly { url: string; alias: string }[]): string { const match = routes.find((route) => value === route.url || value.startsWith(`${route.url}?`)); return match ? `redacted://${match.alias}` : value; }

function redactObjectPairAssertion<T extends { objectId: string; expectedOwnerValue?: string; expectedTenantValue?: string }>(assertion: T): T {
  return {
    ...assertion,
    objectId: "<redacted>",
    ...(assertion.expectedOwnerValue ? { expectedOwnerValue: `<principal:${hashValue(assertion.expectedOwnerValue)}>` } : {}),
    ...(assertion.expectedTenantValue ? { expectedTenantValue: `<tenant:${hashValue(assertion.expectedTenantValue)}>` } : {})
  };
}

function objectIdRedactionPairs(plan: ScanContextOptions["plan"]): Array<{ id: string; hash: string }> {
  return (
    [
      ...(plan.objectPairTesting?.cases.flatMap((testCase) => [
      { id: testCase.accountAObject.objectId, hash: testCase.accountAObject.objectIdHash },
      { id: testCase.accountBObject.objectId, hash: testCase.accountBObject.objectIdHash }
      ]) ?? []),
      ...(plan.fieldExposureTesting?.cases.map((testCase) => ({ id: testCase.objectId, hash: testCase.objectIdHash })) ?? [])
      ,
      ...(plan.authorizationMatrixTesting?.requestMatrix.map((testCase) => ({ id: testCase.objectId, hash: testCase.objectIdHash })) ?? [])
      ,
      ...(plan.collectionAuthorizationTesting?.requestMatrix.flatMap((testCase) => (testCase.objectId && testCase.objectIdHash ? [{ id: testCase.objectId, hash: testCase.objectIdHash }] : [])) ?? [])
      ,
      ...(plan.bulkAuthorizationTesting?.requestMatrix.flatMap((testCase) => testCase.objects.map((object) => ({ id: object.objectId, hash: object.objectIdHash }))) ?? [])
      ,
      ...(plan.fileAuthorizationTesting?.requestMatrix.map((testCase) => ({ id: testCase.fileRef, hash: testCase.fileRefHash })) ?? [])
      ,
      ...(plan.equivalentRouteTesting?.requestMatrix.map((cell) => ({ id: cell.objectId, hash: cell.objectIdHash })) ?? []),
      ...(plan.supabaseAuthorization?.cases.flatMap((testCase) => [
        ...testCase.identityAssertions.flatMap((assertion) => typeof assertion.expectedValue === "string" ? [{ id: assertion.expectedValue, hash: assertion.expectedValueHash }] : []),
        ...(testCase.signedUrl?.expectedPathContains ? [{ id: testCase.signedUrl.expectedPathContains.split("/").filter(Boolean).at(-1) ?? testCase.signedUrl.expectedPathContains, hash: hashValue(testCase.signedUrl.expectedPathContains) }] : [])
      ]) ?? [])
    ]
  );
}

function redactBulkAuthorizationCase<
  T extends {
    url: string;
    body?: string;
    objects: Array<{ objectId: string; objectIdHash: string; state?: string; baseline?: { url: string } }> | readonly { objectId: string; objectIdHash: string; state?: string; baseline?: { url: string } }[];
    postconditionChecks?: readonly { url: string; objectId: string; objectIdHash: string }[];
  }
>(testCase: T): T {
  const pairs = testCase.objects.map((object) => ({ id: object.objectId, hash: object.objectIdHash }));
  return {
    ...testCase,
    url: redactObjectIds(testCase.url, pairs),
    ...(testCase.body ? { body: redactObjectIds(testCase.body, pairs) } : {}),
    ...(testCase.postconditionChecks ? { postconditionChecks: testCase.postconditionChecks.map((check) => ({ ...check, objectId: "<redacted>", url: redactObjectIds(check.url, pairs) })) } : {}),
    objects: testCase.objects.map((object) => ({
      ...object,
      objectId: "<redacted>",
      ...(object.baseline ? { baseline: { ...object.baseline, url: redactObjectIds(object.baseline.url, pairs) } } : {}),
      ...(object.state ? { state: `<state:${hashValue(object.state)}>` } : {})
    }))
  };
}

function redactFileAuthorizationCase<T extends { url: string; fileRef: string; fileRefHash: string }>(testCase: T): T {
  return {
    ...testCase,
    fileRef: "<redacted>",
    url: redactFileRefs(testCase.url, [{ id: testCase.fileRef, hash: testCase.fileRefHash }])
  };
}

function redactFileRefs(value: string, refs: Array<{ id: string; hash: string }>): string {
  return refs.reduce((current, ref) => current.split(encodeURIComponent(ref.id)).join(`<file:${ref.hash}>`).split(ref.id).join(`<file:${ref.hash}>`), value);
}

function redactKnownCollectionObject<T extends { objectId: string; objectIdHash: string; state?: string }>(knownObject: T): T {
  return {
    ...knownObject,
    objectId: "<redacted>",
    ...(knownObject.state ? { state: `<state:${hashValue(knownObject.state)}>` } : {})
  };
}

function redactCollectionAuthorizationCase<T extends { objectId?: string; objectIdHash?: string; url: string; expectedObjectState?: string }>(testCase: T): T {
  const pairs = testCase.objectId && testCase.objectIdHash ? [{ id: testCase.objectId, hash: testCase.objectIdHash }] : [];
  return {
    ...testCase,
    ...(testCase.objectId ? { objectId: "<redacted>" } : {}),
    url: redactObjectIds(testCase.url, pairs),
    ...(testCase.expectedObjectState ? { expectedObjectState: `<state:${hashValue(testCase.expectedObjectState)}>` } : {})
  };
}

function redactAuthorizationMatrixCase<T extends { objectId: string; objectIdHash: string; url: string; expectedObjectState?: string }>(testCase: T): T {
  return {
    ...testCase,
    objectId: "<redacted>",
    url: redactObjectIds(testCase.url, [{ id: testCase.objectId, hash: testCase.objectIdHash }]),
    ...(testCase.expectedObjectState ? { expectedObjectState: `<state:${hashValue(testCase.expectedObjectState)}>` } : {})
  };
}

function redactEquivalentRouteCell<T extends { objectId: string; objectIdHash: string; url: string; expectedObjectState?: string }>(cell: T): T {
  return {
    ...cell,
    objectId: "<redacted>",
    url: redactObjectIds(cell.url, [{ id: cell.objectId, hash: cell.objectIdHash }]),
    ...(cell.expectedObjectState ? { expectedObjectState: `<state:${hashValue(cell.expectedObjectState)}>` } : {})
  };
}

function redactFieldExposureObjectConfirmation<T extends { expectedOwnerHash?: string; expectedTenantHash?: string }>(confirmation: T): T {
  return {
    ...confirmation,
    ...(confirmation.expectedOwnerHash ? { expectedOwnerHash: `<principal:${confirmation.expectedOwnerHash}>` } : {}),
    ...(confirmation.expectedTenantHash ? { expectedTenantHash: `<tenant:${confirmation.expectedTenantHash}>` } : {})
  };
}

function redactFieldExpectation<T extends { path: string; label: string }>(expectation: T): T {
  if (!/(?:token|secret|password|api[_-]?key|session|cookie)/i.test(expectation.path)) {
    return expectation;
  }
  return {
    ...expectation,
    path: `<field:${hashValue(expectation.path)}>`,
    label: expectation.label.replace(/(?:token|secret|password|api[_-]?key|session|cookie)[^.\s]*/gi, "<sensitive-label>")
  };
}

function redactObjectIds(url: string, objectIds: Array<{ id: string; hash: string }>): string {
  return objectIds.reduce((safeUrl, objectId) => {
    return safeUrl.split(encodeURIComponent(objectId.id)).join(`<object:${objectId.hash}>`).split(objectId.id).join(`<object:${objectId.hash}>`);
  }, url);
}

function hashValue(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function redactSupabaseQuery(value: string, enabled: boolean): string {
  if (!enabled) return value;
  try {
    const url = new URL(value);
    for (const name of [...new Set([...url.searchParams.keys()])]) url.searchParams.set(name, "<redacted>");
    return url.toString();
  } catch {
    return value;
  }
}
