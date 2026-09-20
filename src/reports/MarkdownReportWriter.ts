import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { durableAtomicWrite } from "../core/offensive/MutationJournal.js";
import type { FalsePositiveStatus, IdentityVerificationResult, ResponseObservation, RouteCairnReport } from "./ReportTypes.js";

export class MarkdownReportWriter {
  public async write(outputDir: string, report: RouteCairnReport): Promise<string> {
    await mkdir(outputDir, { recursive: true });
    const reportPath = join(outputDir, "report.md");
    await durableAtomicWrite(reportPath, renderMarkdown(report));
    return reportPath;
  }
}

function renderMarkdown(report: RouteCairnReport): string {
  const findings = report.discoveredUrls.filter((item) => item.falsePositiveStatus !== "likely-false-positive");

  return [
    "# RouteCairn Report",
    "",
    ...(report.execution?.partial ? ["> PARTIAL REPORT — " + report.execution.reason, ""] : []),
    ...(report.execution && report.execution.cleanup.state !== "CLEAR" ? ["> CLEANUP " + report.execution.cleanup.state + " — verify recovery before reusing disposable state.", ""] : []),
    "## Scan Metadata",
    "",
    `- Target: ${report.target}`,
    `- Program: ${report.program}`,
    `- Mode: ${report.mode}`,
    ...(report.profile
      ? [
          `- Profile: ${report.profile.displayName} (${report.profile.name})`,
          `- Profile focus: ${report.profile.reportFocus.join(", ")}`,
          `- Browser use: ${report.profile.browserUse}`,
          `- Auth comparison depth: ${report.profile.authComparisonDepth}`,
          `- Proof mode: ${report.profile.proofMode ? "yes" : "no"}`
        ]
      : []),
    `- Started: ${report.metadata.startedAt}`,
    `- Completed: ${report.metadata.completedAt}`,
    `- Duration: ${report.metadata.durationMs} ms`,
    `- Total requests: ${report.metadata.totalRequests}`,
    ...(report.requestBudget ? [
      `- Scan request capacity: ${report.requestBudget.scanCapacity}`,
      `- Cleanup capacity reserved: ${report.requestBudget.cleanupReservedRequests}`,
      `- Ordinary / cleanup transmitted: ${report.requestBudget.scanTransmitted} / ${report.requestBudget.cleanupTransmitted}`,
      `- Ordinary / cleanup remaining: ${report.requestBudget.scanRemaining} / ${report.requestBudget.cleanupRemaining}`
    ] : []),
    ...(report.transport ? [
      `- Connection pooling: ${report.transport.poolingEnabled ? "enabled" : "disabled"}`,
      `- Constrained HTTP/2: ${report.transport.http2Enabled ? "enabled for TLS origins" : "disabled"}`,
      `- Origin pool hits / misses: ${report.transport.poolHits} / ${report.transport.poolMisses}`,
      `- Connections created / estimated reuses: ${report.transport.connectionsCreated} / ${report.transport.estimatedConnectionReuses}`,
      `- HTTP/1.1 / HTTP/2 connections: ${report.transport.http1Connections} / ${report.transport.http2Connections}`,
      `- DNS resolutions / cache hits / blocked: ${report.transport.dnsResolutions} / ${report.transport.dnsCacheHits} / ${report.transport.blockedResolutions}`,
      `- Pin rotations / origin evictions: ${report.transport.pinRotations} / ${report.transport.originEvictions}`
    ] : []),
    `- Technologies detected: ${report.technologies.length}`,
    "",
    "## Technologies Detected",
    "",
    ...technologyTable(report),
    "",
    "## JavaScript Intelligence",
    "",
    ...jsIntelligenceLines(report),
    "",
    "## Browser Intelligence",
    "",
    ...browserCrawlLines(report),
    "",
    "## Baseline",
    "",
    ...baselineLines(report),
    "",
    "## Path Discovery Summary",
    "",
    `- URLs checked: ${report.discoveredUrls.length}`,
    `- Likely valid: ${countByStatus(report.discoveredUrls, "likely-valid")}`,
    `- Maybe false positive: ${countByStatus(report.discoveredUrls, "maybe-false-positive")}`,
    `- Likely false positive: ${countByStatus(report.discoveredUrls, "likely-false-positive")}`,
    `- Cleanup-required mutation cases: ${report.privilegeMutation?.cleanupRequired ?? 0}`,
    "",
    "## Controlled Mutation Verification",
    "",
    ...privilegeMutationLines(report),
    "",
    "## Findings",
    "",
    ...findingTable(report),
    "",
    "## Vulnerability Workflows",
    "",
    ...vulnerabilityWorkflowLines(report),
    "",
    "## Proof Mode Evidence",
    "",
    ...proofModeLines(report),
    "",
    "## Proof Details",
    "",
    ...proofDetails(report),
    "",
    "## Manual Test Pack",
    "",
    ...manualTestPackLines(report),
    "",
    "## API Manual Testing Map",
    "",
    ...apiManualTestingMap(report),
    "",
    "## API Probe",
    "",
    ...apiProbeLines(report),
    "",
    "## Auth Surface Map",
    "",
    ...authSurfaceMap(report),
    "",
    "## Authenticated Comparisons",
    "",
    ...authenticatedComparisonLines(report),
    "",
    "## Identity Verification",
    "",
    ...identityVerificationLines(report),
    "",
    "## Role Comparison",
    "",
    ...roleComparisonLines(report),
    "",
    "## State-Aware API Testing",
    "",
    ...stateAwareApiLines(report),
    "",
    "## Object Pair Testing",
    "",
    ...objectPairTestingLines(report),
    "",
    "## Field Exposure Testing",
    "",
    ...fieldExposureTestingLines(report),
    "",
    "## Authorization Matrix Testing",
    "",
    ...authorizationMatrixTestingLines(report),
    "",
    "## Collection Authorization Testing",
    "",
    ...collectionAuthorizationTestingLines(report),
    "",
    "## Bulk Authorization Testing",
    "",
    ...bulkAuthorizationTestingLines(report),
    "",
    "## File Authorization Testing",
    "",
    ...fileAuthorizationTestingLines(report),
    "",
    "## Equivalent Route Testing",
    "",
    ...equivalentRouteTestingLines(report),
    "",
    "## Supabase Authorization",
    "",
    ...supabaseAuthorizationLines(report),
    "",
    "## Authentication Lifecycle",
    "",
    ...authenticationLifecycleLines(report),
    "",
    "## Business Invariant Validation",
    "",
    ...businessInvariantLines(report),
    "",
    "## Controlled Race Testing",
    "",
    ...controlledRaceLines(report),
    "",
    "## API and GraphQL Authorization",
    "",
    ...apiGraphqlLines(report),
    "",
    "## Protocol-Level Security",
    "",
    ...protocolSecurityLines(report),
    "",
    "## Signed Links, Portals, Invites, and Exports",
    "",
    ...linkPortalSecurityLines(report),
    "",
    "## Webhook, Cron, and Operational Endpoints",
    "",
    ...operationalEndpointSecurityLines(report),
    "",
    "## Checkout, Billing, Entitlement, and Premium Security",
    "",
    ...billingEntitlementLines(report),
    "",
    "## Secret Boundary and Sensitive Exposure",
    "",
    ...secretBoundaryLines(report),
    "",
    "## Active Vulnerability Validation",
    "",
    ...activeVulnerabilityLines(report),
    "",
    "## Assisted Security Review",
    "",
    ...assistedReviewLines(report),
    "",
    "## Parameter Analysis",
    "",
    ...parameterAnalysisLines(report),
    "",
    "## Next.js Review",
    "",
    ...nextJsReviewLines(report),
    "",
    "## Interesting Results",
    "",
    ...observationTable(findings),
    "",
    "## All Discovered URLs",
    "",
    ...observationTable(report.discoveredUrls),
    ""
  ].join("\n");
}

function activeVulnerabilityLines(report: RouteCairnReport): string[] {
  const review = report.activeVulnerability;
  if (!review?.enabled) return ["Active vulnerability validation was not configured."];
  return [
    `- Cases: ${review.plannedCases} (${review.explicitCases} explicit, ${review.discoveredCases} discovery-compiled)`,
    `- Proven / secure / inconclusive / blocked / not assessed: ${review.provenCases} / ${review.secureCases} / ${review.inconclusiveCases} / ${review.blockedCases} / ${review.notAssessedCases}`,
    `- Requests: ${review.requestsTransmitted} / ${review.requestBudget}`,
    "",
    "| Class | Planned | Proven | Secure | Inconclusive | Blocked | Not assessed |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ...review.coverage.map((value) => `| ${value.vulnerabilityClass} | ${value.planned} | ${value.proven} | ${value.secure} | ${value.inconclusive} | ${value.blocked} | ${value.notAssessed} |`)
  ];
}

function assistedReviewLines(report: RouteCairnReport): string[] {
  const review = report.assistedReview;
  if (!review) return ["No assisted-review manifest was supplied."];
  return [`- Gate: ${review.completionGate.state}`, `- Pending human review: ${review.humanReviewQueue.length}`, `- Blockers: ${review.completionGate.blockers.join(", ") || "none"}`, "- This is an operator report, not a human-approved customer publication.", "", "| Lane | Proven | Inconclusive | Not assessed | Blocked | Cleanup unresolved |", "| --- | ---: | ---: | ---: | ---: | ---: |", ...Object.entries(review.coverageMatrix).filter(([, value]) => value.selected).map(([lane, value]) => `| ${lane} | ${value.outcomes.PROVEN} | ${value.outcomes.INCONCLUSIVE} | ${value.outcomes.NOT_ASSESSED} | ${value.outcomes.BLOCKED} | ${value.cleanupFailures} |`)];
}

function billingEntitlementLines(report: RouteCairnReport): string[] {
  const review = report.billingEntitlement;
  if (!review?.enabled) return ["No explicit synthetic billing and entitlement manifest was supplied."];
  const covered = Object.entries(review.coverage).filter(([, value]) => value.planned > 0).map(([category, value]) => `${category}=${value.executed}/${value.planned}`).join(", ");
  return [
    `- Provider boundary: ${review.providerKind ?? "unknown"} / ${review.providerMode ?? "unknown"}`,
    `- Real payment execution: ${review.realPaymentExecution}`,
    `- Cases executed: ${review.executedCases}/${review.plannedCases}`,
    `- Passed / failed: ${review.passedCases} / ${review.failedCases}`,
    `- Inconclusive / blocked: ${review.inconclusiveCases} / ${review.blockedCases}`,
    `- Requests: ${review.requestsTransmitted}/${review.requestBudget}`,
    `- Synchronized groups: ${review.synchronizedGroups}`,
    `- Cleanup failed: ${review.cleanupFailed}`,
    `- Coverage: ${covered || "none"}`,
    ...review.notes.map((note) => `- ${note}`),
    "",
    "| Case | Category | Actors | Endpoints | Outcome | Cleanup | Fingerprint |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...review.observations.map((item) => `| ${escapeCell(item.caseId)} | ${item.category} | ${item.actorAliases.map(escapeCell).join(", ")} | ${item.endpointAliases.map(escapeCell).join(", ")} | ${item.outcome} | ${item.cleanupOutcome} | ${item.comparisonFingerprint.slice(0, 16)} |`),
    "",
    "Billing evidence contains no real payment, payment instrument, provider credential, synthetic event value, account identifier, request body, response body, or raw capture."
  ];
}

function secretBoundaryLines(report: RouteCairnReport): string[] {
  const review = report.secretBoundary;
  if (!review?.enabled) return ["The secret-boundary engine was not selected."];
  const covered = Object.entries(review.coverage).filter(([, value]) => value.sourcesObserved > 0 || value.classifiedObservations > 0).map(([surface, value]) => `${surface}=${value.classifiedObservations}/${value.sourcesObserved}`).join(", ");
  return [
    `- Responses / additional probes / source maps: ${review.observedResponsesReviewed} / ${review.additionalRequestsUsed} / ${review.sourceMapsReviewed}`,
    `- Candidates analyzed: ${review.candidatesAnalyzed}/${review.candidateLimit}`,
    `- Classified observations / confirmed findings: ${review.classifiedObservations} / ${review.confirmedFindings}`,
    `- Client-safe / server-only material: ${review.clientSafeMaterial} / ${review.serverOnlyMaterial}`,
    `- Client-safe naming conflicts: ${review.clientSafeNameConflicts}`,
    `- Supabase anon / publishable / service-role: ${review.supabase.anonKeys} / ${review.supabase.publishableKeys} / ${review.supabase.serviceRoleKeys}`,
    `- Coverage: ${covered || "no classified sources"}`,
    "- Raw values are excluded; observation fingerprints are scoped and non-reversible.",
    ...review.notes.map((note) => `- ${note}`)
  ];
}

function operationalEndpointSecurityLines(report: RouteCairnReport): string[] {
  const review = report.operationalEndpointSecurity;
  if (!review?.enabled) return ["No explicit operational-endpoint security manifest was supplied."];
  const covered = Object.entries(review.coverage).filter(([, value]) => value.planned > 0).map(([category, value]) => `${category}=${value.executed}/${value.planned}`).join(", ");
  return [
    `- Endpoints: ${review.endpointInventory.length}`,
    `- Cases executed: ${review.executedCases}/${review.plannedCases}`,
    `- Passed / failed: ${review.passedCases} / ${review.failedCases}`,
    `- Inconclusive / blocked: ${review.inconclusiveCases} / ${review.blockedCases}`,
    `- Requests: ${review.requestsTransmitted}/${review.requestBudget}`,
    `- Cleanup failed: ${review.cleanupFailed}`,
    `- Coverage: ${covered || "none"}`,
    ...review.notes.map((note) => `- ${note}`),
    "",
    "| Case | Category | Actors | Endpoints | Outcome | Cleanup | Fingerprint |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...review.observations.map((item) => `| ${escapeCell(item.caseId)} | ${item.category} | ${item.actorAliases.map(escapeCell).join(", ")} | ${item.endpointAliases.map(escapeCell).join(", ")} | ${item.outcome} | ${item.cleanupOutcome} | ${item.comparisonFingerprint.slice(0, 16)} |`),
    "",
    "Operational evidence retains safe endpoint paths and fingerprints only; signatures, webhook bodies, event/job identifiers, captures, credentials, and response values are omitted."
  ];
}

function linkPortalSecurityLines(report: RouteCairnReport): string[] {
  const review = report.linkPortalSecurity;
  if (!review?.enabled) return ["No explicit link/portal/export security manifest was supplied."];
  const covered = Object.entries(review.coverage).filter(([, value]) => value.planned > 0).map(([category, value]) => `${category}=${value.executed}/${value.planned}`).join(", ");
  return [
    `- Resources: ${review.resourceInventory.length}`,
    `- Cases executed: ${review.executedCases}/${review.plannedCases}`,
    `- Passed / failed: ${review.passedCases} / ${review.failedCases}`,
    `- Inconclusive / blocked: ${review.inconclusiveCases} / ${review.blockedCases}`,
    `- Requests: ${review.requestsTransmitted}/${review.requestBudget}`,
    `- Cleanup failed: ${review.cleanupFailed}`,
    `- Coverage: ${covered || "none"}`,
    ...review.notes.map((note) => `- ${note}`),
    "",
    "| Case | Category | Actors | Resources | Outcome | Cleanup | Fingerprint |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...review.observations.map((item) => `| ${escapeCell(item.caseId)} | ${item.category} | ${item.actorAliases.map(escapeCell).join(", ")} | ${item.resourceAliases.map(escapeCell).join(", ")} | ${item.outcome} | ${item.cleanupOutcome} | ${item.comparisonFingerprint.slice(0, 16)} |`),
    "",
    "Link evidence contains safe resource paths and fingerprints only; signed values, invites, emails, object identifiers, captures, request bodies, and response bodies are omitted."
  ];
}

function apiGraphqlLines(report: RouteCairnReport): string[] {
  const review = report.apiGraphql;
  if (!review?.enabled) return ["No explicit API/GraphQL review manifest was supplied."];
  return [
    `- Inventory routes: ${review.inventory.length}`,
    `- Checks executed: ${review.executedChecks}/${review.plannedChecks}`,
    `- Passed: ${review.passedChecks}`,
    `- Failed: ${review.failedChecks}`,
    `- Inconclusive: ${review.inconclusiveChecks}`,
    `- Blocked: ${review.blockedChecks}`,
    `- REST / GraphQL checks: ${review.restChecks} / ${review.graphqlChecks}`,
    `- Requests: ${review.requestsTransmitted}/${review.requestBudget}`,
    `- Schema comparisons: ${review.schemaComparisons.length}`,
    ...review.notes.map((note) => `- ${note}`),
    "",
    "| Check | Kind | Actor | Routes | Outcome | Reason | Fingerprint |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...review.checks.map((item) => `| ${escapeCell(item.checkId)} | ${item.kind} | ${escapeCell(item.actorAlias)} | ${item.routeAliases.map(escapeCell).join(", ")} | ${item.outcome} | ${item.reasonCode} | ${item.comparisonFingerprint.slice(0, 16)} |`),
    "",
    "API/GraphQL evidence omits credentials, request bodies, variables, response values, object identities, and tenant identities."
  ];
}

function protocolSecurityLines(report: RouteCairnReport): string[] {
  const review = report.protocolSecurity;
  if (!review?.enabled) return ["No explicit protocol-security manifest was supplied."];
  return [
    `- Cases executed: ${review.executedCases}/${review.plannedCases}`,
    `- Passed / failed / inconclusive / blocked: ${review.passedCases} / ${review.failedCases} / ${review.inconclusiveCases} / ${review.blockedCases}`,
    ...review.notes.map((note) => `- ${note}`),
    "",
    "| Case | Kind | Actor | Outcome | Reason | Status | Messages | Events | Protocol | Cleanup |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ...review.observations.map((item) => `| ${escapeCell(item.caseId)} | ${item.kind} | ${escapeCell(item.actorAlias)} | ${item.outcome} | ${item.reason} | ${item.statusCode ?? "-"} | ${item.messageCount} | ${item.eventCount} | ${item.negotiatedProtocol ?? "-"} | ${item.cleanupOutcome ?? "-"} |`),
    "",
    "Protocol evidence retains counts, status, negotiated protocol, outcomes, and fingerprints only; message, event, protobuf, upload, variable, credential, and response payloads are omitted."
  ];
}

function controlledRaceLines(report: RouteCairnReport): string[] {
  const race = report.controlledRace;
  if (!race?.enabled) return ["No explicit controlled-race manifest was supplied."];
  const covered = Object.entries(race.coverage).filter(([, value]) => value.planned > 0).map(([category, value]) => `${category}=${value.executed}/${value.planned}`).join(", ");
  return [
    `- Planned cases: ${race.plannedCases}`,
    `- Executed cases: ${race.executedCases}`,
    `- Passed: ${race.passedCases}`,
    `- Failed: ${race.failedCases}`,
    `- Inconclusive: ${race.inconclusiveCases}`,
    `- Blocked: ${race.blockedCases}`,
    `- Synchronized groups: ${race.synchronizedGroups}/${race.plannedGroups}`,
    `- Race requests transmitted: ${race.transmittedRaceRequests}/${race.plannedRaceRequests}`,
    `- Cleanup failed: ${race.cleanupFailed}`,
    `- Coverage: ${covered || "none"}`,
    ...race.notes.map((note) => `- ${note}`),
    "",
    "| Case | Category | Outcome | Cleanup | Pre-state | Post-state | Groups | Fingerprint |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...race.observations.map((item) => `| ${escapeCell(item.caseId)} | ${item.category} | ${item.outcome} | ${item.cleanupOutcome} | ${item.preStateVerified ? "verified" : "unverified"} | ${item.postStateVerified ? "verified" : "unverified"} | ${item.groups.filter((group) => group.synchronized).length}/${item.groups.length} | ${item.comparisonFingerprint.slice(0, 16)} |`),
    "",
    "Race evidence contains no credentials, raw target state, request bodies, response bodies, tokens, operator identities, or change tickets."
  ];
}

function businessInvariantLines(report: RouteCairnReport): string[] {
  const invariant = report.businessInvariant;
  if (!invariant?.enabled) return ["No explicit business-invariant manifest was supplied."];
  const covered = Object.entries(invariant.coverage).filter(([, value]) => value.planned > 0).map(([category, value]) => `${category}=${value.executed}/${value.planned}`).join(", ");
  return [
    `- Planned cases: ${invariant.plannedCases}`,
    `- Executed cases: ${invariant.executedCases}`,
    `- Passed: ${invariant.passedCases}`,
    `- Failed: ${invariant.failedCases}`,
    `- Inconclusive: ${invariant.inconclusiveCases}`,
    `- Blocked: ${invariant.blockedCases}`,
    `- Cleanup required: ${invariant.cleanupRequired}`,
    `- Cleanup failed: ${invariant.cleanupFailed}`,
    `- Duplicate attempts: ${invariant.duplicateAttempts}`,
    `- Concurrent actions: ${invariant.concurrentActions}`,
    `- Coverage: ${covered || "none"}`,
    ...invariant.notes.map((note) => `- ${note}`),
    "",
    "| Case | Category | Outcome | Cleanup | Pre-state | Post-state | Actions | Fingerprint |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...invariant.observations.map((item) => `| ${escapeCell(item.caseId)} | ${item.category} | ${item.outcome} | ${item.cleanupOutcome} | ${item.preStateVerified ? "verified" : "unverified"} | ${item.postStateVerified ? "verified" : "unverified"} | ${item.actions.length} | ${item.comparisonFingerprint.slice(0, 16)} |`),
    "",
    "Invariant evidence intentionally contains no credentials, authorization identities, raw business state, response bodies, or account identifiers."
  ];
}

function authenticationLifecycleLines(report: RouteCairnReport): string[] {
  const lifecycle = report.authenticationLifecycle;
  if (!lifecycle?.enabled) return ["No explicit authentication lifecycle manifest was supplied."];
  const covered = Object.entries(lifecycle.coverage).filter(([, value]) => value.planned > 0).map(([category, value]) => `${category}=${value.executed}/${value.planned}`).join(", ");
  return [
    `- Planned cases: ${lifecycle.plannedCases}`,
    `- Executed cases: ${lifecycle.executedCases}`,
    `- Passed: ${lifecycle.passedCases}`,
    `- Failed: ${lifecycle.failedCases}`,
    `- Inconclusive: ${lifecycle.inconclusiveCases}`,
    `- Blocked: ${lifecycle.blockedCases}`,
    `- Cleanup required: ${lifecycle.cleanupRequired}`,
    `- Cleanup failed: ${lifecycle.cleanupFailed}`,
    ...(lifecycle.learningAutomation ? [
      `- Browser-learned automation: enabled`,
      `- Automatically generated categories: ${lifecycle.learningAutomation.generatedCategories.join(", ") || "none"}`,
      `- Automation blockers: ${lifecycle.learningAutomation.blockers.length}`,
      `- Redacted automation artifact: ${lifecycle.learningAutomation.artifactPath}`
    ] : []),
    `- Coverage: ${covered || "none"}`,
    ...lifecycle.notes.map((note) => `- ${note}`),
    "",
    "| Case | Category | Outcome | Cleanup | Fingerprint | Steps |",
    "| --- | --- | --- | --- | --- | --- |",
    ...lifecycle.observations.map((item) => `| ${escapeCell(item.caseId)} | ${item.category} | ${item.outcome} | ${item.cleanupOutcome} | ${item.comparisonFingerprint.slice(0, 16)} | ${item.steps.length} |`),
    "",
    "Lifecycle evidence intentionally contains no credentials, tokens, email addresses, recovery codes, or raw account identifiers."
  ];
}

function supabaseAuthorizationLines(report: RouteCairnReport): string[] {
  const supabase = report.supabaseAuthorization;
  if (!supabase?.enabled) return ["No explicit Supabase authorization manifest was supplied."];
  const coverage = Object.entries(supabase.coverage).map(([name, covered]) => `${name}=${covered ? "covered" : "not-covered"}`).join(", ");
  return [
    `- Project origin: ${supabase.projectOrigin ?? "unknown"}`,
    `- Planned cases: ${supabase.plannedCases}`,
    `- Executed cases: ${supabase.executedCases}`,
    `- Confirmed issues: ${supabase.confirmedIssues}`,
    `- Anon key classification: ${supabase.anonKeyClassification}`,
    `- Service-role configured: ${supabase.serviceRoleConfigured}`,
    `- Service-role boundary verified: ${supabase.serviceRoleBoundaryVerified}`,
    `- Coverage: ${coverage}`,
    ...supabase.notes.map((note) => `- ${note}`),
    "",
    "| Case | Surface | Resource | Actor | Operation | Expected | Observed | Identity | Sensitive columns | Finding |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ...supabase.observations.map((item) => `| ${escapeCell(item.caseId)} | ${item.surface} | ${escapeCell(item.resource)} | ${item.actor} | ${item.operation} | ${item.expectedDecision} | ${item.observedDecision} | ${item.identityConfirmed ? "confirmed" : "unconfirmed"} | ${escapeCell(item.sensitiveColumnsObserved.join(", ") || "none")} | ${item.findingCategory ?? "none"} |`),
    "",
    "| Catalog risk | Severity | Resource | Summary |",
    "| --- | --- | --- | --- |",
    ...supabase.staticRisks.map((item) => `| ${item.category} | ${item.severity} | ${escapeCell(item.resource)} | ${escapeCell(item.summary)} |`)
  ];
}

function identityVerificationLines(report: RouteCairnReport): string[] {
  if (!report.identityVerification || !report.identityVerification.enabled) {
    return ["No identity verification was configured."];
  }

  const rows: Array<[string, IdentityVerificationResult]> = [];
  if (report.identityVerification.primary) rows.push(["Primary", report.identityVerification.primary]);
  if (report.identityVerification.accountA) rows.push(["Account A", report.identityVerification.accountA]);
  if (report.identityVerification.accountB) rows.push(["Account B", report.identityVerification.accountB]);

  return [
    ...report.identityVerification.notes.map((note) => `- ${note}`),
    ...(typeof report.identityVerification.distinctVerifiedPrincipals === "boolean"
      ? [`- Distinct verified principals: ${report.identityVerification.distinctVerifiedPrincipals}`]
      : []),
    "",
    "| Profile | Mode | Category | Verified | Principal Match | Tenant Match | Role Match |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...rows.map(([label, result]) =>
      `| ${[
        label,
        result.mode,
        result.category,
        String(result.verified),
        String(result.principalMatched),
        result.tenantMatched === undefined ? "n/a" : String(result.tenantMatched),
        result.roleMatched === undefined ? "n/a" : String(result.roleMatched)
      ].join(" | ")} |`
    )
  ];
}

function objectPairTestingLines(report: RouteCairnReport): string[] {
  if (!report.objectPairTesting || !report.objectPairTesting.enabled) {
    return ["No object-pair testing was run."];
  }

  return [
    `- Planned cases: ${report.objectPairTesting.plannedCases}`,
    `- Planned requests: ${report.objectPairTesting.plannedRequests}`,
    `- Executed requests: ${report.objectPairTesting.executedRequests}`,
    `- Confirmed controlled issues: ${report.objectPairTesting.confirmedIssues}`,
    ...report.objectPairTesting.notes.map((note) => `- ${note}`),
    "",
    "| Case | Object Type | A Baseline | B Baseline | A to B | B to A |",
    "| --- | --- | --- | --- | --- | --- |",
    ...report.objectPairTesting.cases.map((testCase) =>
      `| ${[
        escapeCell(testCase.caseId),
        escapeCell(testCase.objectType),
        testCase.baselineA.category,
        testCase.baselineB.category,
        testCase.aToB.category,
        testCase.bToA.category
      ].join(" | ")} |`
    )
  ];
}

function fieldExposureTestingLines(report: RouteCairnReport): string[] {
  if (!report.fieldExposureTesting || !report.fieldExposureTesting.enabled) {
    return ["No field-exposure testing was run."];
  }

  return [
    `- Planned cases: ${report.fieldExposureTesting.plannedCases}`,
    `- Planned requests: ${report.fieldExposureTesting.plannedRequests}`,
    `- Executed requests: ${report.fieldExposureTesting.executedRequests}`,
    `- Confirmed controlled issues: ${report.fieldExposureTesting.confirmedIssues}`,
    ...report.fieldExposureTesting.notes.map((note) => `- ${note}`),
    "",
    "| Case | Object Type | Object Hash | Visibility | Requests | Issues |",
    "| --- | --- | --- | --- | ---: | ---: |",
    ...report.fieldExposureTesting.cases.map((testCase) =>
      `| ${[
        escapeCell(testCase.caseId),
        escapeCell(testCase.objectType),
        testCase.objectIdHash,
        testCase.expectedVisibility,
        testCase.executedRequests.toString(),
        testCase.confirmedIssues.length.toString()
      ].join(" | ")} |`
    )
  ];
}

function authorizationMatrixTestingLines(report: RouteCairnReport): string[] {
  if (!report.authorizationMatrix || !report.authorizationMatrix.enabled) {
    return ["No authorization matrix testing was run."];
  }

  return [
    `- Planned matrices: ${report.authorizationMatrix.plannedMatrices}`,
    `- Planned cases: ${report.authorizationMatrix.plannedCases}`,
    `- Planned requests: ${report.authorizationMatrix.plannedRequests}`,
    `- Executed requests: ${report.authorizationMatrix.executedRequests}`,
    `- Confirmed controlled issues: ${report.authorizationMatrix.confirmedIssues}`,
    ...report.authorizationMatrix.notes.map((note) => `- ${note}`),
    "",
    "| Matrix | Case | Actor | Relationship | Object Hash | Expected | Observed | Finding |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...report.authorizationMatrix.cases.map((testCase) =>
      `| ${[
        escapeCell(testCase.matrixId),
        escapeCell(testCase.caseId),
        escapeCell(testCase.actorId),
        escapeCell(testCase.actorRelationship),
        testCase.objectIdHash,
        testCase.expectedDecision,
        testCase.observedDecision,
        testCase.findingCategory ?? "none"
      ].join(" | ")} |`
    )
  ];
}

function collectionAuthorizationTestingLines(report: RouteCairnReport): string[] {
  if (!report.collectionAuthorization || !report.collectionAuthorization.enabled) {
    return ["No collection authorization testing was run."];
  }

  return [
    `- Planned collections: ${report.collectionAuthorization.plannedCollections}`,
    `- Planned cases: ${report.collectionAuthorization.plannedCases}`,
    `- Planned requests: ${report.collectionAuthorization.plannedRequests}`,
    `- Executed requests: ${report.collectionAuthorization.executedRequests}`,
    `- Confirmed controlled issues: ${report.collectionAuthorization.confirmedIssues}`,
    ...report.collectionAuthorization.notes.map((note) => `- ${note}`),
    "",
    "| Collection | Case | Actor | Object Hash | Expected | Membership | Decision | Finding |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...report.collectionAuthorization.observations.map((observation) =>
      `| ${[
        escapeCell(observation.collectionLabel),
        escapeCell(observation.caseId),
        escapeCell(observation.actorId),
        observation.objectIdHash ?? "none",
        observation.expectedMembership,
        observation.observedMembership,
        observation.observedDecision,
        observation.findingCategory ?? "none"
      ].join(" | ")} |`
    )
  ];
}

function bulkAuthorizationTestingLines(report: RouteCairnReport): string[] {
  if (!report.bulkAuthorization || !report.bulkAuthorization.enabled) {
    return ["No bulk authorization testing was run."];
  }
  return [
    `- Planned definitions: ${report.bulkAuthorization.plannedDefinitions}`,
    `- Planned cases: ${report.bulkAuthorization.plannedCases}`,
    `- Planned requests: ${report.bulkAuthorization.plannedRequests}`,
    `- Executed requests: ${report.bulkAuthorization.executedRequests}`,
    `- Confirmed controlled issues: ${report.bulkAuthorization.confirmedIssues}`,
    ...report.bulkAuthorization.notes.map((note) => `- ${note}`),
    "",
    "| Definition | Case | Actor | Operation | Policy | Observed | Finding |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...report.bulkAuthorization.observations.map((observation) =>
      `| ${[
        escapeCell(observation.definitionId),
        escapeCell(observation.caseId),
        escapeCell(observation.actorId),
        observation.operationType,
        observation.expectedBatchPolicy,
        observation.observedDecision,
        observation.findingCategory ?? "none"
      ].join(" | ")} |`
    )
  ];
}

function fileAuthorizationTestingLines(report: RouteCairnReport): string[] {
  if (!report.fileAuthorization || !report.fileAuthorization.enabled) {
    return ["File authorization testing was not enabled."];
  }
  return [
    `- Planned definitions: ${report.fileAuthorization.plannedDefinitions}`,
    `- Planned cases: ${report.fileAuthorization.plannedCases}`,
    `- Planned requests: ${report.fileAuthorization.plannedRequests}`,
    `- Executed requests: ${report.fileAuthorization.executedRequests}`,
    `- Confirmed controlled issues: ${report.fileAuthorization.confirmedIssues}`,
    ...report.fileAuthorization.notes.map((note) => `- ${note}`),
    "",
    "| Case | Actor | File | Expected | Observed | Proof | Bytes | Finding |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...report.fileAuthorization.observations.map((observation) =>
      `| ${observation.caseId} | ${observation.actorId} | ${observation.fileAlias} | ${observation.expectedDecision} | ${observation.observedDecision} | ${observation.contentProofMode} | ${observation.bytesObserved} | ${observation.findingCategory ?? ""} |`
    )
  ];
}

function equivalentRouteTestingLines(report: RouteCairnReport): string[] {
  if (!report.equivalentRouteTesting || !report.equivalentRouteTesting.enabled) {
    return ["No equivalent-route testing was run."];
  }

  return [
    `- Planned route sets: ${report.equivalentRouteTesting.plannedRouteSets}`,
    `- Planned routes: ${report.equivalentRouteTesting.plannedRoutes}`,
    `- Planned requests: ${report.equivalentRouteTesting.plannedRequests}`,
    `- Executed requests: ${report.equivalentRouteTesting.executedRequests}`,
    `- Confirmed controlled issues: ${report.equivalentRouteTesting.confirmedIssues}`,
    ...report.equivalentRouteTesting.notes.map((note) => `- ${note}`),
    "",
    "| Route Set | Actor | Route | Category | Object Hash | Expected | Observed | Finding |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...report.equivalentRouteTesting.observations.map((observation) =>
      `| ${[
        escapeCell(observation.routeSetId),
        escapeCell(observation.actorId),
        escapeCell(observation.routeLabel),
        escapeCell(observation.routeCategory),
        observation.objectIdHash,
        observation.expectedDecision,
        observation.observedDecision,
        observation.findingCategory ?? "none"
      ].join(" | ")} |`
    )
  ];
}

function browserCrawlLines(report: RouteCairnReport): string[] {
  if (!report.browserCrawl) {
    return ["No browser crawl was recorded."];
  }

  return [
    `- Start URL: ${report.browserCrawl.startUrl}`,
    `- Screenshot: ${report.browserCrawl.screenshotPath ?? "none"}`,
    `- Rendered links: ${report.browserCrawl.renderedLinks.length}`,
    `- Network requests: ${report.browserCrawl.networkRequests.length}`,
    `- Console warnings/errors: ${report.browserCrawl.consoleErrors.length}`,
    `- Forms detected: ${report.browserCrawl.formsDetected}`,
    `- Forms submitted: ${report.browserCrawl.formsSubmitted}`,
    ...(report.browserCrawl.authentication ? [
      `- Authenticated bootstrap: ${report.browserCrawl.authentication.bootstrapSucceeded ? "succeeded" : "failed"} (${report.browserCrawl.authentication.mode})`,
      `- Session isolated: ${report.browserCrawl.authentication.sessionIsolated}`,
      `- Redacted HAR: ${report.browserCrawl.authentication.redactedHarPath ?? "none"}`,
      `- Cookie/storage metadata observations: ${report.browserCrawl.authentication.storage.length}`,
      `- Writable/read-only field observations: ${report.browserCrawl.authentication.fields.length}`,
      `- Admin routes from legitimate navigation: ${report.browserCrawl.authentication.adminRoutes.length}`,
      `- Learned draft test cases: ${report.browserCrawl.authentication.learnedTestCases.length}`,
      `- Mutation authority from learned traffic: none; ${report.browserCrawl.authentication.protectedActionProof}`,
      `- Browser restarts: ${report.browserCrawl.authentication.browserRestartCount}`
    ] : []),
    "",
    ...report.browserCrawl.notes.map((note) => `- ${note}`)
  ];
}

function apiManualTestingMap(report: RouteCairnReport): string[] {
  if (!report.apiMapper || report.apiMapper.endpoints.length === 0) {
    return ["No API endpoints mapped."];
  }

  return [
    ...report.apiMapper.notes.map((note) => `- ${note}`),
    "",
    "| Endpoint | Type | Tags | Suggested Tests |",
    "| --- | --- | --- | --- |",
    ...report.apiMapper.endpoints.map((endpoint) =>
      `| ${[
        escapeCell(endpoint.endpoint),
        endpoint.routeType,
        escapeCell(endpoint.riskTags.join(", ")),
        escapeCell(endpoint.likelyManualTests.join("; "))
      ].join(" | ")} |`
    )
  ];
}

function apiProbeLines(report: RouteCairnReport): string[] {
  if (!report.apiProbe || report.apiProbe.endpointsReviewed.length === 0) {
    return ["No API probe reviews recorded."];
  }

  return [
    `- Safe methods: ${report.apiProbe.safeMethods.join(", ")}`,
    `- Skipped methods: ${report.apiProbe.skippedMethods.join(", ")}`,
    `- Schema hints: ${report.apiProbe.schemaHints.length === 0 ? "none" : escapeText(report.apiProbe.schemaHints.join(", "))}`,
    `- GraphQL endpoints probed: ${report.apiProbe.graphQlEndpoints.length}`,
    ...report.apiProbe.notes.map((note) => `- ${note}`),
    "",
    "| Endpoint | OPTIONS | HEAD | GET | Content Types | Allowed Methods | Schema Hints | GraphQL |",
    "| --- | ---: | ---: | ---: | --- | --- | --- | --- |",
    ...report.apiProbe.endpointsReviewed.map((review) =>
      `| ${[
        escapeCell(review.endpoint),
        String(review.statusByMethod.OPTIONS ?? "error"),
        String(review.statusByMethod.HEAD ?? "error"),
        String(review.statusByMethod.GET ?? "error"),
        escapeCell(review.contentTypes.join(", ") || "none"),
        escapeCell(review.allowedMethods.join(", ") || "none"),
        escapeCell(review.schemaHints.join(", ") || "none"),
        review.graphQl.attempted ? (review.graphQl.available ? "introspection-like evidence" : "checked safely") : "skipped"
      ].join(" | ")} |`
    )
  ];
}

function authSurfaceMap(report: RouteCairnReport): string[] {
  if (!report.authSurface || report.authSurface.surfaces.length === 0) {
    return ["No auth surfaces mapped."];
  }

  return [
    ...report.authSurface.notes.map((note) => `- ${note}`),
    "",
    "| Endpoint | Purpose | Abuse Categories | Suggested Tests |",
    "| --- | --- | --- | --- |",
    ...report.authSurface.surfaces.map((surface) =>
      `| ${[
        escapeCell(surface.endpoint),
        surface.purpose,
        escapeCell(surface.abuseCategories.join(", ")),
        escapeCell(surface.suggestedTests.join("; "))
      ].join(" | ")} |`
    )
  ];
}

function authenticatedComparisonLines(report: RouteCairnReport): string[] {
  if (!report.authenticatedScan || !report.authenticatedScan.profile.enabled) {
    return ["No auth profile supplied. Run with --auth ./examples/auth.example.json to compare public and authenticated behavior."];
  }

  const rows = report.authenticatedScan.results.filter((result) => result.classification !== "same-access");

  return [
    `- Profile: ${report.authenticatedScan.profile.label ?? "authenticated"}` ,
    `- Compared URLs: ${report.authenticatedScan.comparedUrls}` ,
    `- Auth-only surfaces: ${report.authenticatedScan.authOnlySurfaces.length}` ,
    `- Changed surfaces: ${report.authenticatedScan.changedSurfaces.length}` ,
    ...report.authenticatedScan.notes.map((note) => `- ${note}`),
    "",
    rows.length === 0 ? "No auth-only or changed-content surfaces recorded." : "| URL | Classification | Anonymous | Authenticated | Reason |",
    ...(rows.length === 0 ? [] : ["| --- | --- | ---: | ---: | --- |"]),
    ...rows.map((result) =>
      `| ${[
        escapeCell(result.url),
        result.classification,
        result.anonymous.statusCode?.toString() ?? "error",
        result.authenticated.statusCode?.toString() ?? "error",
        escapeCell(result.reason)
      ].join(" | ")} |`
    )
  ];
}

function roleComparisonLines(report: RouteCairnReport): string[] {
  if (!report.roleComparison || !report.roleComparison.profileSet.enabled) {
    return ["No account A/account B profiles supplied. Run with --auth-a and --auth-b to compare roles."];
  }

  const rows = report.roleComparison.results.filter((result) => result.classification !== "same-as-anonymous");

  return [
    `- Compared URLs: ${report.roleComparison.comparedUrls}` ,
    `- Account A only: ${report.roleComparison.accountAOnly.length}` ,
    `- Account B only: ${report.roleComparison.accountBOnly.length}` ,
    `- Only authenticated access: ${report.roleComparison.onlyAuthenticatedAccess.length}` ,
    ...report.roleComparison.notes.map((note) => `- ${note}`),
    "",
    rows.length === 0 ? "No role differences or private authenticated surfaces recorded." : "| URL | Classification | Anonymous | Account A | Account B | Manual Verification | Reason |",
    ...(rows.length === 0 ? [] : ["| --- | --- | ---: | ---: | ---: | --- | --- |"]),
    ...rows.map((result) =>
      `| ${[
        escapeCell(result.url),
        result.classification,
        result.anonymous.statusCode?.toString() ?? "error",
        result.accountA.statusCode?.toString() ?? "error",
        result.accountB.statusCode?.toString() ?? "error",
        result.needsManualVerification ? "yes" : "no",
        escapeCell(result.reason)
      ].join(" | ")} |`
    )
  ];
}

function stateAwareApiLines(report: RouteCairnReport): string[] {
  if (!report.stateAwareApi || report.stateAwareApi.reviewedEndpoints.length === 0) {
    return ["No state-aware API candidates were reviewed."];
  }

  return [
    `- Safe methods: ${report.stateAwareApi.safeMethods.join(", ")}` ,
    `- Skipped mutating methods: ${report.stateAwareApi.skippedMethods.join(", ")}` ,
    `- Candidate endpoints: ${report.stateAwareApi.candidateCount}` ,
    `- BOLA/IDOR candidates: ${report.stateAwareApi.bolaIdorCandidates.length}` ,
    ...report.stateAwareApi.notes.map((note) => `- ${note}`),
    "",
    "| Endpoint | Priority | Reasons | Signal | GET | HEAD | OPTIONS | Manual Verification |",
    "| --- | --- | --- | --- | ---: | ---: | ---: | --- |",
    ...report.stateAwareApi.reviewedEndpoints.map((review) => {
      const statusFor = (method: string) => review.safeMethodsTested.find((item) => item.method === method)?.statusCode?.toString() ?? "error";
      return `| ${[
        escapeCell(review.endpoint),
        review.priority,
        escapeCell(review.candidateReasons.join(", ")),
        review.accessComparison.signal,
        statusFor("GET"),
        statusFor("HEAD"),
        statusFor("OPTIONS"),
        review.accessComparison.needsManualVerification ? "yes" : "no"
      ].join(" | ")} |`;
    })
  ];
}

function nextJsReviewLines(report: RouteCairnReport): string[] {
  if (!report.nextJsReview || !report.nextJsReview.detected) {
    return ["Next.js was not detected or no Next.js review was run."];
  }

  return [
    "### Technology intelligence",
    "",
    `- Detection confidence: ${report.nextJsReview.detectionConfidence ?? "unknown"}`,
    `- Router classification: ${report.nextJsReview.routerKind ?? "UNKNOWN"}`,
    `- Detection evidence: ${escapeText(report.nextJsReview.detectionEvidence?.join(", ") || "none")}`,
    `- Build ID metadata: ${report.nextJsReview.buildIds.length === 0 ? "none" : escapeText(report.nextJsReview.buildIds.join(", "))}`,
    "",
    "### Observed public surfaces",
    "",
    `- Normalized surfaces: ${report.nextJsReview.surfaces?.length ?? 0}`,
    `- Public manifests parsed/reviewed: ${report.nextJsReview.manifests?.length ?? 0}`,
    `- _next/data routes reviewed: ${report.nextJsReview.dataRoutes.length}`,
    `- Source maps classified: ${report.nextJsReview.sourceMaps.length}`,
    `- Cache/data signals: ${report.nextJsReview.cacheSignals.length}`,
    "",
    "### Coverage",
    "",
    `- Module state: ${report.nextJsReview.coverage?.moduleState ?? "unknown"}`,
    `- Data review: ${report.nextJsReview.coverage?.dataSurfaceReview ?? "unknown"}`,
    `- Source-map review: ${report.nextJsReview.coverage?.sourceMapReview ?? "unknown"}`,
    `- Cache differential: ${report.nextJsReview.coverage?.cacheDifferential ?? "unknown"}`,
    `- Additional request ceiling: ${report.nextJsReview.requestBudget?.maximumAdditionalRequests ?? 0}`,
    "",
    "### Security findings",
    "",
    ...Object.entries(report.nextJsReview.securityFindingCounts ?? {}).map(([type, count]) => `- ${escapeText(type)}: ${count}`),
    ...(Object.keys(report.nextJsReview.securityFindingCounts ?? {}).length === 0 ? ["- None from Next.js deep review."] : []),
    "",
    "### Review limitations",
    "",
    ...(report.nextJsReview.coverage?.limitations ?? []).map((limitation) => `- ${escapeText(limitation)}`),
    ...report.nextJsReview.notes.map((note) => `- ${note}`),
    "",
    report.nextJsReview.dataRoutes.length === 0 ? "No _next/data routes reviewed." : "| URL | Status | Cache Risk | Indicators | Cache-Control |",
    ...(report.nextJsReview.dataRoutes.length === 0 ? [] : ["| --- | ---: | --- | --- | --- |"]),
    ...report.nextJsReview.dataRoutes.map((route) =>
      `| ${[
        escapeCell(route.url),
        route.statusCode?.toString() ?? "error",
        route.cacheRisk,
        escapeCell(route.dataIndicators.join(", ") || "none"),
        escapeCell(route.cacheControl ?? "")
      ].join(" | ")} |`
    ),
    "",
    report.nextJsReview.sourceMaps.length === 0 ? "No source maps classified." : "| Source Map | Classification | Severity Hint | Reason |",
    ...(report.nextJsReview.sourceMaps.length === 0 ? [] : ["| --- | --- | --- | --- |"]),
    ...report.nextJsReview.sourceMaps.map((sourceMap) =>
      `| ${[escapeCell(sourceMap.url), sourceMap.classification, sourceMap.severityHint, escapeCell(sourceMap.reason)].join(" | ")} |`
    )
  ];
}

function parameterAnalysisLines(report: RouteCairnReport): string[] {
  if (!report.parameterAnalysis || report.parameterAnalysis.totalParameters === 0) {
    return ["No parameters were identified."];
  }

  const highRiskRows = report.parameterAnalysis.analyzedUrls.flatMap((analysis) =>
    analysis.parameters
      .filter((parameter) => parameter.riskTags.includes("authorization-sensitive") || parameter.riskTags.includes("business-logic"))
      .map((parameter) => ({ url: analysis.url, parameter }))
  );

  return [
    `- Total parameters: ${report.parameterAnalysis.totalParameters}` ,
    `- High-risk parameters: ${report.parameterAnalysis.highRiskParameters.length}` ,
    `- Object ID tags: ${report.parameterAnalysis.riskSummary.objectId}` ,
    `- Authorization-sensitive tags: ${report.parameterAnalysis.riskSummary.authorizationSensitive}` ,
    `- Business-logic tags: ${report.parameterAnalysis.riskSummary.businessLogic}` ,
    ...report.parameterAnalysis.notes.map((note) => `- ${note}`),
    "",
    highRiskRows.length === 0 ? "No high-risk parameters identified." : "| URL | Name | Location | Kind | Tags | Confidence |",
    ...(highRiskRows.length === 0 ? [] : ["| --- | --- | --- | --- | --- | --- |"]),
    ...highRiskRows.map(({ url, parameter }) =>
      `| ${[
        escapeCell(url),
        escapeCell(parameter.name),
        parameter.location,
        parameter.kind,
        escapeCell(parameter.riskTags.join(", ")),
        parameter.confidence
      ].join(" | ")} |`
    )
  ];
}

function jsIntelligenceLines(report: RouteCairnReport): string[] {
  if (!report.jsIntelligence) {
    return ["No JavaScript intelligence was recorded."];
  }

  return [
    `- Scripts discovered: ${report.jsIntelligence.scripts.length}`,
    `- Same-origin scripts downloaded: ${report.jsIntelligence.scripts.filter((script) => script.downloaded).length}`,
    `- Queued JS endpoints: ${report.jsIntelligence.queuedEndpoints.length}`,
    `- Source maps detected: ${report.jsIntelligence.sourceMaps.length}`,
    `- Config-looking values: ${report.jsIntelligence.scripts.reduce((total, script) => total + script.configValues.length, 0)}`,
    "",
    ...report.jsIntelligence.notes.map((note) => `- ${note}`)
  ];
}

function technologyTable(report: RouteCairnReport): string[] {
  if (report.technologies.length === 0) {
    return ["No technologies detected."];
  }

  return [
    "| Technology | Category | Confidence | Signals |",
    "| --- | --- | --- | --- |",
    ...report.technologies.map((technology) =>
      `| ${[
        escapeCell(technology.name),
        technology.category,
        technology.confidence,
        escapeCell(technology.signals.join(", "))
      ].join(" | ")} |`
    )
  ];
}

function findingTable(report: RouteCairnReport): string[] {
  if (report.findings.length === 0) {
    return ["No findings."];
  }

  return [
    "| Title | Severity | Confidence | Risk | URL | Source |",
    "| --- | --- | --- | ---: | --- | --- |",
    ...report.findings.map((finding) =>
      `| ${[
        escapeCell(finding.title),
        finding.severity,
        finding.confidence,
        finding.riskScore.toString(),
        escapeCell(finding.url),
        finding.sourceModule
      ].join(" | ")} |`
    )
  ];
}

function manualTestPackLines(report: RouteCairnReport): string[] {
  if (!report.workflowValidation || report.workflowValidation.templates.length === 0) {
    return ["No manual test pack templates generated."];
  }

  return [
    ...report.workflowValidation.notes.map((note) => `- ${note}`),
    "",
    ...report.workflowValidation.templates.flatMap((template, index) => [
      `### ${index + 1}. ${template.title}`,
      "",
      `- Kind: ${template.kind}`,
      `- Priority: ${template.priority}`,
      `- Target: ${escapeText(template.target)}`,
      `- Needs manual verification: ${template.needsManualVerification ? "yes" : "no"}`,
      `- Related endpoints: ${template.relatedEndpoints.length === 0 ? "none" : escapeText(template.relatedEndpoints.slice(0, 8).join(", "))}`,
      "",
      "Preconditions:",
      "",
      ...template.preconditions.map((item) => `- ${escapeText(item)}`),
      "",
      "Steps:",
      "",
      ...template.steps.map((item) => `- ${escapeText(item)}`),
      "",
      "Expected secure behavior:",
      "",
      ...template.expectedSecureBehavior.map((item) => `- ${escapeText(item)}`),
      "",
      "Evidence to capture:",
      "",
      ...template.evidenceToCapture.map((item) => `- ${escapeText(item)}`),
      "",
      "Do not:",
      "",
      ...template.avoidActions.map((item) => `- ${escapeText(item)}`),
      ""
    ])
  ];
}

function vulnerabilityWorkflowLines(report: RouteCairnReport): string[] {
  if (!report.vulnerabilityWorkflows || report.vulnerabilityWorkflows.workflows.length === 0) {
    return ["No vulnerability workflows generated."];
  }

  return [
    ...report.vulnerabilityWorkflows.notes.map((note) => `- ${note}`),
    "",
    ...report.vulnerabilityWorkflows.workflows.flatMap((workflow, index) => [
      `### ${index + 1}. ${workflow.title}`,
      "",
      `- Category: ${workflow.category}`,
      `- Priority: ${workflow.priority}`,
      `- Confidence: ${workflow.confidence}`,
      `- Target: ${escapeText(workflow.target)}`,
      `- Evidence: ${escapeText(workflow.evidence.join(" "))}`,
      `- Related endpoints: ${workflow.relatedEndpoints.length === 0 ? "none" : escapeText(workflow.relatedEndpoints.slice(0, 10).join(", "))}`,
      "",
      "Safe test plan:",
      "",
      ...workflow.safeTestPlan.map((step) => `- ${escapeText(step)}`),
      "",
      "Avoid:",
      "",
      ...workflow.avoidActions.map((action) => `- ${escapeText(action)}`),
      ""
    ])
  ];
}
function proofDetails(report: RouteCairnReport): string[] {
  const proofFindings = report.findings
    .filter((finding) => ["Critical", "High", "Medium"].includes(finding.severity))
    .sort((left, right) => right.riskScore - left.riskScore)
    .slice(0, 20);

  if (proofFindings.length === 0) {
    return ["No Critical, High, or Medium proof blocks. Full finding evidence is stored in report.json."];
  }

  return proofFindings.flatMap((finding, index) => [
    `### ${index + 1}. ${finding.title}`,
    "",
    `- Severity: ${finding.severity}`,
    `- Confidence: ${finding.confidence}`,
    `- Risk: ${finding.riskScore}`,
    `- URL: ${finding.url}`,
    `- Status: ${finding.evidence.statusCode ?? "unknown"}`,
    `- Content length: ${finding.evidence.contentLength ?? "unknown"}`,
    `- Evidence: ${escapeText(finding.evidence.source ?? "none")}`,
    `- Severity reason: ${escapeText(finding.evidence.severityReason ?? "not recorded")}`,
    "",
    "```bash",
    finding.evidence.curlCommand ?? `curl -i \"${finding.url.replace(/\"/g, "\\\\\"")}\"`,
    "```",
    "",
    ...(finding.evidence.bodyPreview ? ["Body preview:", "", "```text", trimForMarkdown(finding.evidence.bodyPreview), "```", ""] : [])
  ]);
}
function baselineLines(report: RouteCairnReport): string[] {
  if (!report.baseline) {
    return ["- No baseline was recorded."];
  }

  return [
    `- Probes: ${report.baseline.probes.length}`,
    `- Wildcard status: ${report.baseline.wildcardStatusCode ?? "none"}`,
    `- Repeated title: ${report.baseline.repeatedTitle ?? "none"}`,
    `- Repeated body hash: ${report.baseline.repeatedBodyHash ? "yes" : "none"}`,
    ...report.baseline.notes.map((note) => `- ${note}`)
  ];
}

function observationTable(observations: ResponseObservation[]): string[] {
  if (observations.length === 0) {
    return ["No results."];
  }

  return [
    "| URL | Status | Title | FP Status | Reason |",
    "| --- | ---: | --- | --- | --- |",
    ...observations.map((item) =>
      `| ${[
        escapeCell(item.url),
        item.statusCode?.toString() ?? "error",
        escapeCell(item.title ?? ""),
        item.falsePositiveStatus,
        escapeCell(item.classificationReason)
      ].join(" | ")} |`
    )
  ];
}

function countByStatus(observations: ResponseObservation[], status: FalsePositiveStatus): number {
  return observations.filter((item) => item.falsePositiveStatus === status).length;
}

function escapeCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function escapeText(value: string): string {
  return value.replace(/\r?\n/g, " ");
}

function trimForMarkdown(value: string): string {
  return value.length > 1200 ? `${value.slice(0, 1200)}\n... <truncated>` : value;
}

function privilegeMutationLines(report: RouteCairnReport): string[] {
  const mutation = report.privilegeMutation;
  if (!mutation) return ["Controlled mutation testing was not selected."];
  return [
    `- Planned cases: ${mutation.plannedCases}`,
    `- Executed cases: ${mutation.executedCases}`,
    `- Proven security findings: ${mutation.provenFindings}`,
    `- Cleanup required: ${mutation.cleanupRequired}`,
    ...mutation.notes.map((note) => `- ${escapeText(note)}`),
    "",
    ...mutation.observations.map((item) => `- ${escapeText(item.caseId)}: intent=${item.intent}; ${item.securityOutcome}; cleanup=${item.cleanupOutcome}; transmitted=${item.requestTransmitted ? "yes" : "no"}; authority-change-verified=${item.authorityChangeVerified ? "yes" : "no"}; browser-protected-action=${item.result.browserProtectedActionVerified === undefined ? "not-configured" : item.result.browserProtectedActionVerified ? "verified" : "failed"}; browser-rollback=${item.result.browserRollbackVerified === undefined ? "not-configured" : item.result.browserRollbackVerified ? "verified" : "failed"}`)
  ];
}

function proofModeLines(report: RouteCairnReport): string[] {
  if (!report.proofMode || report.proofMode.blocks.length === 0) {
    return ["No Proof Mode blocks generated. Run with --profile proof or another proof-enabled profile."];
  }

  return [
    ...report.proofMode.notes.map((note) => `- ${note}`),
    "",
    ...report.proofMode.blocks.flatMap((block, index) => [
      `### ${index + 1}. ${block.title}`,
      "",
      `- Target: ${escapeText(block.target)}`,
      `- Severity: ${block.severity}`,
      `- Needs manual verification: ${block.needsManualVerification ? "yes" : "no"}`,
      `- Why selected: ${escapeText(block.whySelected.join(", "))}`,
      `- Severity reason: ${escapeText(block.severityReason)}`,
      "",
      "Stable evidence:",
      "",
      ...block.stableEvidence.map((item) => `- ${escapeText(item)}`),
      "",
      "Requests:",
      "",
      ...block.comparisons.map((comparison) => `- ${comparison.label}: ${escapeText(comparison.request.curlCommand)} => ${comparison.response.statusCode ?? "error"}, ${comparison.response.contentType ?? "unknown"}, ${comparison.response.contentLength ?? "unknown"} bytes`),
      "",
      "Bounty summary:",
      "",
      escapeText(block.bountySubmissionSummary),
      ""
    ])
  ];
}
