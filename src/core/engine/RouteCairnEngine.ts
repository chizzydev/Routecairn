import { createHash } from "node:crypto";
import { ScanContext, type ScanContextOptions } from "./ScanContext.js";
import { ScanOrchestrator } from "./ScanOrchestrator.js";
import { JsonReportWriter } from "../../reports/JsonReportWriter.js";
import { MarkdownReportWriter } from "../../reports/MarkdownReportWriter.js";
import { HtmlReportWriter } from "../../reports/HtmlReportWriter.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { legacyModeForProfile, profileSummary } from "../../config/ScanProfiles.js";
import { verifyScanIdentities } from "../auth/IdentityVerification.js";
import { ScanCancelledError } from "./ScanEvents.js";

export class RouteCairnEngine {
  private readonly orchestrator = new ScanOrchestrator();
  private readonly jsonReportWriter = new JsonReportWriter();
  private readonly markdownReportWriter = new MarkdownReportWriter();
  private readonly htmlReportWriter = new HtmlReportWriter();

  public async scan(options: ScanContextOptions): Promise<{ reportPath: string; markdownReportPath: string; htmlReportPath: string }> {
    const context = new ScanContext(options);

    try {
      const identityVerification = await verifyScanIdentities(context);
      if (identityVerification) {
        context.state.recordIdentityVerification(identityVerification);
      }

      await this.orchestrator.run(context);
    } catch (error) {
      context.state.complete();
      if (error instanceof ScanCancelledError || options.abortSignal?.aborted) {
        await options.eventSink?.emit({ type: "SCAN_CANCELLED", message: "Scan cancelled by operator." });
      } else {
        await options.eventSink?.emit({ type: "SCAN_FAILED", message: error instanceof Error ? error.message : "Scan failed with an unknown error." });
        throw error;
      }
    }
    const stateReport = safeStateReportForReport(context.state.toReport(options.plan), options.plan);

    const report: RouteCairnReport = {
      routeCairnVersion: "0.1.0",
      target: options.target,
      mode: options.plan.metadata.legacyMode ?? legacyModeForProfile(options.plan.profile),
      profile: profileSummary(options.plan),
      scanPlan: safePlanForReport(options.plan),
      program: options.scope.program,
      scope: {
        allowedDomains: options.scope.allowedDomains,
        disallowedPaths: options.scope.disallowedPaths,
        allowedMethods: options.scope.allowedMethods,
        rateLimitPerSecond: options.plan.limits.rateLimitPerSecond,
        concurrency: options.plan.limits.concurrency,
        sameOriginOnly: options.scope.sameOriginOnly,
        includeSubdomains: options.scope.includeSubdomains
      },
      ...stateReport
    };

    const reportPath = await this.jsonReportWriter.write(options.outputDir, report);
    const markdownReportPath = await this.markdownReportWriter.write(options.outputDir, report);
    const htmlReportPath = await this.htmlReportWriter.write(options.outputDir, report);
    await options.eventSink?.emit({ type: "REPORT_WRITTEN", message: "Reports written.", metadata: { reportPath, markdownReportPath, htmlReportPath } });

    return { reportPath, markdownReportPath, htmlReportPath };
  }
}

function safeStateReportForReport<T extends ReturnType<ScanContext["state"]["toReport"]>>(stateReport: T, plan: ScanContextOptions["plan"]): T {
  if (!plan.objectPairTesting && !plan.fieldExposureTesting && !plan.authorizationMatrixTesting && !plan.collectionAuthorizationTesting && !plan.bulkAuthorizationTesting && !plan.fileAuthorizationTesting && !plan.equivalentRouteTesting) {
    return stateReport;
  }

  const objectIds = objectIdRedactionPairs(plan);
  return {
    ...stateReport,
    requestAudit: stateReport.requestAudit.map((entry) => ({
      ...entry,
      requestedUrl: redactObjectIds(entry.requestedUrl, objectIds),
      ...(entry.finalUrl ? { finalUrl: redactObjectIds(entry.finalUrl, objectIds) } : {}),
      redirectChain: entry.redirectChain.map((hop) => ({ ...hop, location: redactObjectIds(hop.location, objectIds) }))
    }))
  };
}

function safePlanForReport(plan: ScanContextOptions["plan"]): ScanContextOptions["plan"] {
  if (!plan.objectPairTesting && !plan.fieldExposureTesting && !plan.authorizationMatrixTesting && !plan.collectionAuthorizationTesting && !plan.bulkAuthorizationTesting && !plan.fileAuthorizationTesting && !plan.equivalentRouteTesting) {
    return plan;
  }

  const objectIds = objectIdRedactionPairs(plan);

  return {
    ...plan,
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
      : {})
  };
}

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
      ...(plan.equivalentRouteTesting?.requestMatrix.map((cell) => ({ id: cell.objectId, hash: cell.objectIdHash })) ?? [])
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
