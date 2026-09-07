import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { startDisposableTarget } from "./DisposableTarget.js";
import { exampleScope } from "../config/defaults.js";
import { scopeSchema } from "../config/ConfigSchema.js";
import { authProfileSchema } from "../core/auth/AuthProfile.js";
import { controlledMutationContractSchema, type ControlledMutationContract } from "../core/offensive/ControlledMutationTypes.js";
import { disposableIdentityFingerprint } from "../modules/preHandover/PreHandoverRuntime.js";
import { DashboardDatabase } from "../dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../dashboard/services/DashboardPaths.js";
import { CredentialVault } from "../dashboard/credentials/CredentialVault.js";
import { ScanExecutionService } from "../dashboard/execution/ScanExecutionService.js";
import { ControlledMutationRecoveryService } from "../dashboard/execution/ControlledMutationRecoveryService.js";
import { ControlledMutationApprovalRepository } from "../dashboard/db/ControlledMutationApprovalRepository.js";
import { TargetRepository } from "../dashboard/db/DashboardRepositories.js";
import { MutationRecoveryVault } from "../core/offensive/MutationRecoveryVault.js";
import { AssistedReviewService } from "../dashboard/reviews/AssistedReviewService.js";
import { FindingCommandCenterService } from "../dashboard/findings/FindingCommandCenterService.js";
import { ProofPackService } from "../dashboard/proofPacks/ProofPackService.js";
import { ComparisonService } from "../dashboard/services/ComparisonService.js";
import { scanStudioSchema } from "../dashboard/contracts/ScanStudioSchemas.js";
import type { DashboardScanCreateRequest } from "../dashboard/types/DashboardTypes.js";
import type { RouteCairnReport } from "../reports/ReportTypes.js";

/** Self-contained acceptance run. No caller-supplied target URL is accepted. */
export async function runLocalTargetValidation(outputParent?: string) {
  if (outputParent) await mkdir(outputParent, { recursive: true });
  const directory = await mkdtemp(join(resolve(outputParent ?? tmpdir()), "routecairn-validation-"));
  const fixture = await startDisposableTarget();
  const paths = resolveDashboardPaths(directory);
  const database = new DashboardDatabase(paths.databasePath); database.migrate();
  const vault = new CredentialVault(database, { bytes: randomBytes(32), version: "disposable-validation" });
  const execution = new ScanExecutionService(database, paths, vault);
  try {
    const origin = fixture.origin;
    const cookies = await Promise.all([fixture.login(0), fixture.login(1)]);
    const scope = scopeSchema.parse({ ...exampleScope, program: "Owned disposable local validation", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH"], rateLimitPerSecond: 20, concurrency: 2 });
    const bootstrap = {
      schemaVersion: 1, loginSecrets: { username: fixture.users[0]!.username, password: fixture.users[0]!.password },
      login: { startUrl: `${origin}/login`, allowedWritePaths: ["/session"], successUrlPrefix: `${origin}/app`, steps: [{ action: "fill", selector: "input[name=username]", valueRef: "username" }, { action: "fill", selector: "input[name=password]", valueRef: "password" }, { action: "click", selector: "button[type=submit]" }, { action: "waitForUrl", urlPrefix: `${origin}/app` }] },
      identitySelectors: { principal: "#principal" }, journeys: [{ id: "admin-navigation", label: "Legitimate admin navigation", steps: [{ action: "clickLink", selector: "#admin-link" }] }],
      proofCases: [{ caseId: "local-role", protectedAction: { url: `${origin}/app`, selector: "#premium", expected: "visible" }, rollback: { url: `${origin}/app`, selector: "#premium", expected: "hidden" } }]
    };
    const profiles = fixture.users.map((user, index) => authProfileSchema.parse({ label: `Account ${index === 0 ? "A" : "B"}`, safeAlias: `fixture-${index}`, principalId: user.id, cookies: [{ name: "fixture_session", value: cookies[index]!.slice("fixture_session=".length) }], identityVerification: { mode: "required", endpoint: `${origin}/me`, principalIdField: "id" }, ...(index === 0 ? { browserBootstrap: bootstrap } : {}) }));
    const credentials = profiles.map((profile) => vault.create({ name: profile.label, safeAlias: profile.safeAlias!, safeIdentitySummary: { principalId: profile.principalId }, secret: { cookies: { fixture_session: profile.cookies[0]!.value }, identityVerification: { endpoint: `${origin}/me`, principalFieldPath: "id" }, ...(profile.browserBootstrap ? { browserBootstrap: profile.browserBootstrap } : {}) } }));
    const manifestPath = join(directory, "invariant.json");
    await writeFile(manifestPath, JSON.stringify(localInvariantManifest(origin)), { mode: 0o600 });
    const caseRef = { workflowId: "business-invariant", caseId: "wallet-limit" };
    const preHandover = {
      schemaVersion: 1 as const, assaultId: "local-acceptance", revision: "before-fix", environment: "LOCAL" as const, targetOrigin: origin,
      environmentVerification: { path: "/environment", field: "environment", expected: "LOCAL" as const },
      setup: { mode: "SUPPLIED_DISPOSABLE_ACCOUNTS" as const, accountA: { path: "/me", disposableField: "disposable" }, accountB: { path: "/me", disposableField: "disposable" } },
      objects: [{ id: "settings-a", owner: "accountA" as const, path: "/settings", disposableField: "disposable", ownerField: "ownerId", identityField: "id", identityFingerprint: disposableIdentityFingerprint("settings-fixture-a"), cases: [caseRef] }],
      invariants: [{ ...caseRef, invariantId: "nonnegative" }], races: [], sequence: ["browser-crawler", "business-invariant"], criticalCases: [caseRef], regressions: [],
      review: { schemaVersion: 1 as const, reviewId: "local-review", title: "Local disposable pre-handover acceptance", focus: ["BROWSER", "AUTHORIZATION"] as const, requiredLanes: ["BROWSER", "AUTHORIZATION"] as const, cases: [{ workflowId: "browser-crawler", caseId: "authenticated-browser-bootstrap", lane: "BROWSER" as const }, { ...caseRef, lane: "AUTHORIZATION" as const }], authentication: { requireVerifiedIdentity: true, requireAccountPair: true }, completionGate: { requireNoBlocked: true, requireNoInconclusive: true, requireHumanReviewForFindings: true as const } }
    };
    const studio = scanStudioSchema.parse({ version: 1, scanName: "Local disposable acceptance", authorization: { category: "CONTROLLED_LAB", confirmed: true }, scope, moduleSettings: { browserCrawler: { browserAllowPrivateNetwork: true, browserAllowedPrivateOrigins: [origin], browserCaptureScreenshot: false, browserMaxPages: 2 } } });
    const request: DashboardScanCreateRequest = { target: `${origin}/app`, profile: "pre-handover", studio, credentialProfileAId: credentials[0]!, credentialProfileBId: credentials[1]!, businessInvariantFile: manifestPath, preHandover: { ...preHandover, review: { ...preHandover.review, focus: [...preHandover.review.focus], requiredLanes: [...preHandover.review.requiredLanes] } }, targetAuthorization: { schemaVersion: 1, mode: "PRE_HANDOVER_ASSAULT", targetOrigin: origin, proof: { reference: "Owned generated loopback fixture", sha256: hash("RouteCairn local acceptance") } }, rateLimitPerSecond: 20 };
    const beforeScan = await executeScan(execution, database, request);
    const beforeReport = JSON.parse(await readFile(join(paths.reportsDir, beforeScan, "report.json"), "utf8")) as RouteCairnReport;
    requireCheck(beforeReport.businessInvariant?.failedCases === 1, "KNOWN_INVARIANT_NOT_DETECTED");
    requireCheck(beforeReport.browserCrawl?.authentication?.bootstrapSucceeded === true, "BROWSER_BOOTSTRAP_FAILED");
    requireCheck(beforeReport.identityVerification?.distinctVerifiedPrincipals === true, "ACTOR_PAIR_NOT_VERIFIED");
    const reviews = new AssistedReviewService(database, paths);
    requireCheck(reviews.get(beforeScan).gate.blockers.includes("PRE_HANDOVER_CRITICAL_WORKFLOW_UNPROVEN"), "HANDOVER_GATE_DID_NOT_BLOCK");
    const finding = reviews.get(beforeScan).queue.find((item) => item.workflowId === "business-invariant");
    requireCheck(Boolean(finding), "STANDARD_FINDING_MISSING");
    const command = new FindingCommandCenterService(database);
    const version = (database.db.prepare("SELECT row_version FROM findings WHERE id = ?").get(finding!.findingId) as { row_version: number }).row_version;
    // This is a simulated review in a NEW isolated fixture database, never a customer/human decision.
    command.review({ findingId: finding!.findingId, newStatus: "CONFIRMED", expectedVersion: version, reason: "Synthetic acceptance decision: known deliberately vulnerable local fixture.", principal: { userId: "local", login: "fixture-acceptance", role: "OWNER", mode: "local", csrfToken: randomBytes(32).toString("base64url") } });
    const proofPackId = new ProofPackService(database, paths).generate("Synthetic local acceptance proof", "Fixture-only simulated review; not a human-approved customer finding.", [finding!.findingId]);
    fixture.setFixed(true);
    const fingerprint = beforeReport.businessInvariant!.observations[0]!.comparisonFingerprint;
    const afterScan = await executeScan(execution, database, { ...request, preHandover: { ...request.preHandover!, revision: "after-fix", regressions: [{ ...caseRef, previousFindingId: finding!.findingId, fixReference: "fixture-balance-guard", comparisonFingerprint: fingerprint }] } });
    requireCheck(reviews.get(afterScan).gate.state === "READY", "FIXED_HANDOVER_NOT_READY");
    const comparison = new ComparisonService(database).compare(beforeScan, afterScan);
    requireCheck(comparison.summary.resolved >= 1, "REGRESSION_COMPARISON_NOT_RESOLVED");

    // Exact operator contracts travel through authenticated worker IPC; credentials come from the vault.
    const targets = new TargetRepository(database);
    const targetId = targets.create({ displayName: "Generated loopback fixture", baseOrigin: origin, tags: ["fixture-only"], classification: "LOCAL", authorizationType: "OWNED", authorizationSummary: "Owned disposable acceptance fixture", approvedScope: scope });
    const target = targets.get(targetId)!;
    const approvals = new ControlledMutationApprovalRepository(database);
    const approve = (contract: ControlledMutationContract) => {
      const binding = { planIdentity: hash(contract.caseId), targetIdentityFingerprint: hash(`${target.id}:${target.rowVersion}:${target.baseOrigin}`), scopeDigest: hash(JSON.stringify(target.approvedScope, Object.keys(target.approvedScope).sort())) };
      const id = approvals.create({ ...binding, caseId: contract.caseId, targetId, targetOrigin: origin, authorizationSummary: "Simulated fixture-only operator approval", expiresAt: contract.authorization.expiresAt });
      approvals.approve(id, "fixture-acceptance");
      return { id, contract: { ...contract, approvalBinding: binding } };
    };
    const mutationRequest: DashboardScanCreateRequest = { target: `${origin}/app`, targetId, profile: "quick", studio, credentialProfileId: credentials[0]!, includeModules: ["baseline", "browser-crawler", "privilege-mutation-testing"], rateLimitPerSecond: 20, concurrency: 2, targetAuthorization: { schemaVersion: 1, mode: "INTERNAL_STAGING", targetOrigin: origin, proof: { reference: "Generated owned fixture", sha256: hash("local-fixture") } } };
    const approved = approve(localRoleContract(origin, "fixture_session=expired-not-a-credential"));
    const proofScan = await executeScan(execution, database, mutationRequest, [approved.contract], approved.id);
    const proofReport = JSON.parse(await readFile(join(paths.reportsDir, proofScan, "report.json"), "utf8")) as RouteCairnReport;
    const proof = proofReport.privilegeMutation?.observations[0]?.result;
    requireCheck(proofReport.scanPlan?.privilegeMutationTesting?.cases[0]?.impact.assertions.every((item) => item.expectedValue === "<redacted>"), "APPROVAL_ASSERTION_VALUE_LEAK");
    requireCheck(proof, "APPROVED_WORKER_MUTATION_MISSING");
    await writeFile(join(directory, "protected-action-proof.json"), JSON.stringify(proof, null, 2), { mode: 0o600 });
    requireCheck(proof.securityOutcome === "EXPLOIT_PROVEN" && proof.protectedActionVerified && proof.browserProtectedActionVerified && proof.browserRollbackVerified && proof.cleanupOutcome === "ROLLBACK_VERIFIED", "PROTECTED_ACTION_OR_BROWSER_ROLLBACK_FAILED");
    requireCheck(approvals.get(approved.id)?.status === "COMPLETED", "APPROVAL_COMPLETION_NOT_RECORDED");
    let duplicateBlocked = false;
    try { await execution.enqueue(mutationRequest, [approved.contract], approved.id); } catch (error) { duplicateBlocked = error instanceof Error && error.message.startsWith("MUTATION_EXECUTION_UNAVAILABLE"); }
    requireCheck(duplicateBlocked, "APPROVAL_REPLAY_NOT_BLOCKED");
    // Independently inject cleanup failure to exercise recovery with a newly issued credential.
    fixture.setCleanupFailure(true);
    const recoveryApproval = approve({ ...localRoleContract(origin, "fixture_session=expired-not-a-credential"), caseId: "local-recovery" });
    const failedScan = await executeScan(execution, database, { ...mutationRequest, includeModules: ["baseline", "privilege-mutation-testing"] }, [recoveryApproval.contract], recoveryApproval.id);
    const failedReport = JSON.parse(await readFile(join(paths.reportsDir, failedScan, "report.json"), "utf8")) as RouteCairnReport;
    requireCheck(failedReport.privilegeMutation?.observations[0]?.result.cleanupOutcome === "CLEANUP_FAILED" && approvals.get(recoveryApproval.id)?.status === "CLEANUP_REQUIRED", "RECOVERY_FAILURE_NOT_RECORDED");
    fixture.setCleanupFailure(false);
    const bundle = (await readdir(paths.mutationJournalDir)).find((name) => name.endsWith(".recovery.enc"));
    requireCheck(Boolean(bundle), "RECOVERY_BUNDLE_MISSING");
    const sealed = await new MutationRecoveryVault(paths.mutationJournalDir).open(join(paths.mutationJournalDir, bundle!), "local-recovery");
    requireCheck(sealed.targetAuthorization?.proof.sha256 === mutationRequest.targetAuthorization?.proof.sha256, "RECOVERY_TARGET_POLICY_NOT_BOUND");
    const freshCookie = await fixture.login(0);
    const recoveryCredential = vault.create({ name: "Fresh recovery session", safeAlias: "fixture-recovery", safeIdentitySummary: { principalId: fixture.users[0]!.id }, secret: { cookies: { fixture_session: freshCookie.slice("fixture_session=".length) } } });
    const recoveryRequest: DashboardScanCreateRequest = { target: origin, profile: "quick", studio, credentialProfileId: recoveryCredential, includeModules: ["baseline"], rateLimitPerSecond: 20, concurrency: 2 };
    const recovery = await new ControlledMutationRecoveryService(database, paths, targets, vault).queueRecovery({ recoveryJobId: randomUUID(), approvalId: recoveryApproval.id, bundlePath: join(paths.mutationJournalDir, bundle!), caseId: "local-recovery", targetId, credentialProfileId: recoveryCredential, workerRequest: recoveryRequest });
    requireCheck(recovery.cleanupOutcome === "ROLLBACK_VERIFIED", "WORKER_RECOVERY_FAILED");
    requireCheck(fixture.snapshot().users.every((user) => user.role === "member" && user.balance === 100), "FIXTURE_NOT_RESTORED");
    requireCheck(fixture.snapshot().staleReads > 0 && !fixture.calls.some((call) => call.path === "/unsafe"), "EVENTUAL_CONSISTENCY_OR_BROWSER_WRITE_BOUNDARY_FAILED");
    const artifacts = database.db.prepare("SELECT canonical_path AS path FROM artifacts").all() as Array<{ path: string }>;
    const secrets = [...cookies.map((cookie) => cookie.slice("fixture_session=".length)), ...fixture.users.map((user) => user.password), freshCookie.slice("fixture_session=".length)];
    for (const artifact of artifacts) { const content = await readFile(artifact.path, "utf8"); requireCheck(secrets.every((secret) => !content.includes(secret)), "ARTIFACT_SECRET_LEAK"); }
    const summary = {
      schemaVersion: 1, status: "PASSED", directory, externalTargetsTested: false,
      fixtureOnly: true, simulatedHumanReview: true, credentialsReusable: false,
      beforeScan, afterScan, proofScan, failedCleanupScan: failedScan,
      proofPackId, comparisonId: comparison.comparisonId,
      checks: {
        realLogin: true, distinctActors: true, encryptedCredentialProfiles: true,
        isolatedWorker: true, authenticatedBrowser: true, learnedMutationsBlocked: true,
        singleUseApproval: true, approvedMutationWorker: true, protectedAction: true,
        browserProtectedAction: true, browserRollback: true, eventualConsistency: true,
        cleanupFailureDetected: true, recoveryPolicyBound: true, freshCredentialWorkerRecovery: true,
        handoverGate: true, fixRegressionComparison: true, artifactsRedacted: true
      },
      requestCount: fixture.calls.length, staleReads: fixture.snapshot().staleReads,
      timelineEvents: (database.db.prepare("SELECT COUNT(*) AS count FROM scan_events").get() as { count: number }).count,
      dashboardDatabase: paths.databasePath
    };
    await writeFile(join(directory, "validation-summary.json"), `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
    return summary;
  } finally { try { await execution.shutdown(); } finally { try { database.close(); } finally { await fixture.close(); } } }
}

async function executeScan(execution: ScanExecutionService, database: DashboardDatabase, request: DashboardScanCreateRequest, contracts?: readonly ControlledMutationContract[], approvalId?: string): Promise<string> {
  const id = await execution.enqueue(request, contracts, approvalId); const deadline = Date.now() + 90000;
  while (Date.now() < deadline) {
    const row = database.db.prepare("SELECT status, error_summary FROM scans WHERE id = ?").get(id) as { status: string; error_summary: string | null };
    if (row.status === "COMPLETED") return id;
    if (["FAILED", "CANCELLED", "INTERRUPTED"].includes(row.status)) throw new Error(`LOCAL_VALIDATION_WORKER_FAILED:${row.error_summary ?? row.status}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  execution.cancel(id); throw new Error("LOCAL_VALIDATION_WORKER_TIMEOUT");
}
function requireCheck(value: unknown, code: string): asserts value { if (!value) throw new Error(`LOCAL_VALIDATION:${code}`); }
function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }

export function localInvariantManifest(origin: string) {
  const read = (id: string, name: string) => ({ id, actorId: "member", request: { method: "GET", url: `${origin}/wallet`, stateChanging: false }, captures: [{ name, source: "JSON", path: "balance" }] });
  return { schemaVersion: 1, maxRequests: 12, cases: [{ id: "wallet-limit", label: "Withdrawal cannot exceed disposable balance", category: "FINANCIAL_LIMIT", actors: [{ id: "member", safeAlias: "fixture-member", authSlot: "account_a", relationship: "SELF", declaredState: "ACTIVE" }], authorization: { mode: "CONTROLLED_INVARIANT", environment: "LOCAL", confirmation: "I_AUTHORIZE_CONTROLLED_BUSINESS_INVARIANT_TESTING", authorizedBy: "fixture-only", changeTicket: "LOCAL-VALIDATION", authorizedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600000).toISOString(), disposableEntities: true }, preState: [read("before", "before_balance")], actions: [{ id: "withdraw", actorId: "member", request: { method: "POST", url: `${origin}/withdraw`, stateChanging: true, bodyFormat: "JSON", fields: { amount: 150 } }, execution: { mode: "ONCE", attempts: 1, maxConcurrency: 1 }, expectation: { authorization: "ALLOW", businessRule: "NOT_EVALUATED" } }], postState: [read("after", "after_balance")], invariants: [{ id: "nonnegative", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "after_balance" }, operator: "GTE", right: { source: "LITERAL", value: 0 } }], cleanupRequired: true, cleanup: [{ id: "restore", actorId: "member", request: { method: "POST", url: `${origin}/restore-wallet`, stateChanging: true }, successStatusCodes: [204] }], cleanupVerification: [read("restored", "restored_balance")], cleanupInvariants: [{ id: "restored", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "restored_balance" }, operator: "EQ", right: { source: "CAPTURE", ref: "before_balance" } }] }] };
}

function localRoleContract(origin: string, cookie: string) {
  const headers = { Cookie: cookie, "Content-Type": "application/json" };
  const identity = { path: "id", operator: "EQUALS", expectedValue: "settings-fixture-a" };
  const verify = (path: string, assertions: unknown[]) => ({ request: { url: `${origin}${path}`, method: "GET", headers, skipCache: true }, assertions, attempts: 4, delayMs: 100 });
  return controlledMutationContractSchema.parse({ schemaVersion: 1, caseId: "local-role", targetOrigin: origin, mode: "CONTROLLED_MUTATION", environment: "LOCAL", authorization: { authorizedBy: "fixture-only", changeTicket: "LOCAL-PROOF", confirmation: "I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY", authorizedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600000).toISOString() }, target: { disposable: true, type: "fixture-settings", alias: "settings-a", identityFingerprint: hash(JSON.stringify("settings-fixture-a")), identityAssertion: identity }, attack: { request: { url: `${origin}/settings`, method: "PATCH", headers, body: '{"role":"admin"}' }, allowedFields: ["role"], allowedValues: { role: ["admin"] }, semanticEffect: "UPDATE_EXISTING" }, precondition: verify("/settings", [identity, { path: "role", operator: "EQUALS", expectedValue: "member" }]), impact: verify("/settings", [{ path: "role", operator: "EQUALS", expectedValue: "admin" }]), protectedAction: verify("/protected", [{ path: "allowed", operator: "EQUALS", expectedValue: true }]), rollback: { request: { url: `${origin}/settings`, method: "PATCH", headers, body: '{"role":"member"}' }, verification: { ...verify("/settings", [identity, { path: "role", operator: "EQUALS", expectedValue: "member" }]), matchPreStateHash: true } } });
}
