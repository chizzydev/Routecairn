import { ScanContext, type ScanContextOptions } from "./ScanContext.js";
import { ScanOrchestrator } from "./ScanOrchestrator.js";
import { JsonReportWriter } from "../../reports/JsonReportWriter.js";
import { MarkdownReportWriter } from "../../reports/MarkdownReportWriter.js";
import { HtmlReportWriter } from "../../reports/HtmlReportWriter.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { legacyModeForProfile, profileSummary } from "../../config/ScanProfiles.js";

export class RouteCairnEngine {
  private readonly orchestrator = new ScanOrchestrator();
  private readonly jsonReportWriter = new JsonReportWriter();
  private readonly markdownReportWriter = new MarkdownReportWriter();
  private readonly htmlReportWriter = new HtmlReportWriter();

  public async scan(options: ScanContextOptions): Promise<{ reportPath: string; markdownReportPath: string; htmlReportPath: string }> {
    const context = new ScanContext(options);

    await this.orchestrator.run(context);

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
      ...context.state.toReport(options.plan)
    };

    const reportPath = await this.jsonReportWriter.write(options.outputDir, report);
    const markdownReportPath = await this.markdownReportWriter.write(options.outputDir, report);
    const htmlReportPath = await this.htmlReportWriter.write(options.outputDir, report);

    return { reportPath, markdownReportPath, htmlReportPath };
  }
}

function safePlanForReport(plan: ScanContextOptions["plan"]): ScanContextOptions["plan"] {
  if (!plan.objectPairTesting) {
    return plan;
  }

  const objectIds = plan.objectPairTesting.cases.flatMap((testCase) => [
    { id: testCase.accountAObject.objectId, hash: testCase.accountAObject.objectIdHash },
    { id: testCase.accountBObject.objectId, hash: testCase.accountBObject.objectIdHash }
  ]);

  return {
    ...plan,
    objectPairTesting: {
      ...plan.objectPairTesting,
      cases: plan.objectPairTesting.cases.map((testCase) => ({
        ...testCase,
        template: { ...testCase.template, urlTemplate: redactObjectIds(testCase.template.urlTemplate, objectIds) },
        accountAObject: { ...testCase.accountAObject, objectId: "<redacted>" },
        accountBObject: { ...testCase.accountBObject, objectId: "<redacted>" },
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
  };
}

function redactObjectIds(url: string, objectIds: Array<{ id: string; hash: string }>): string {
  return objectIds.reduce((safeUrl, objectId) => {
    return safeUrl.split(encodeURIComponent(objectId.id)).join(`<object:${objectId.hash}>`).split(objectId.id).join(`<object:${objectId.hash}>`);
  }, url);
}
