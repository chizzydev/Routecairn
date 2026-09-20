import type { RouteCairnConfig, RouteCairnScope } from "../../config/ConfigSchema.js";
import type { AuthProfile } from "../auth/AuthProfile.js";
import type { AuthProfileSet } from "../auth/AuthProfileSet.js";
import type { ControlledMutationContract, ControlledMutationResult } from "../offensive/ControlledMutationTypes.js";
import { ControlledMutationExecutor } from "../offensive/ControlledMutationExecutor.js";
import { RequestSafetyBroker } from "../http/RequestSafetyBroker.js";
import type { ModuleId, ModuleSettings, ResolvedScanPlan } from "../planning/ScanPlan.js";
import { ScopeMatcher } from "../scope/ScopeMatcher.js";
import { noopScanEventSink, type ScanEventSink } from "./ScanEvents.js";
import { ScanState } from "./ScanState.js";
import { browserPolicyFromSettings } from "../../modules/browserCrawler/BrowserPolicy.js";
import { BrowserProofVerifier } from "../../modules/browserCrawler/BrowserProofVerifier.js";
import { TargetAuthorizationGuard } from "../authorization/TargetAuthorization.js";
import { WorkflowMutationCoordinator, type WorkflowCheckpoint } from "../offensive/WorkflowMutationCoordinator.js";
import { CleanupExecution } from "./CleanupExecution.js";
import type { ModuleResult } from "../plugins/Plugin.js";
import { ScanRequestLedger, type RequestLedgerLane } from "../http/ScanRequestLedger.js";
import { PinnedOriginPool } from "../http/PinnedOriginPool.js";

export interface ScanContextOptions {
  target: string;
  scope: RouteCairnScope;
  config: RouteCairnConfig;
  plan: ResolvedScanPlan;
  outputDir: string;
  mutationJournalDir?: string;
  workflowRecovery?: WorkflowCheckpoint;
  recoveryScope?: RouteCairnScope;
  authProfile?: AuthProfile;
  authProfileSet?: AuthProfileSet;
  eventSink?: ScanEventSink;
  abortSignal?: AbortSignal;
  /** Internal durability hook; only already-redacted report data is persisted. */
  checkpointReport?: () => Promise<void>;
  controlledMutationContracts?: readonly import("../offensive/ControlledMutationTypes.js").ControlledMutationContract[];
}

export class ScanContext {
  public readonly mutations: WorkflowMutationCoordinator;
  public readonly scopeMatcher: ScopeMatcher;
  public readonly httpClient: RequestSafetyBroker;
  public readonly requestLedger: ScanRequestLedger;
  public readonly state = new ScanState();
  public readonly eventSink: ScanEventSink;
  private readonly cleanupWindows = new Map<RequestSafetyBroker, CleanupExecution>();
  private readonly cleanupAnnounced = new WeakSet<RequestSafetyBroker>();
  private readonly cancellationCleanup: CleanupExecution;
  private readonly connectionPool: PinnedOriginPool;
  public readonly partialModules = new Map<string, () => ModuleResult>();

  public constructor(public readonly options: ScanContextOptions) {
    this.cancellationCleanup = new CleanupExecution(undefined, options.abortSignal);
    this.connectionPool = new PinnedOriginPool(options.config.transport);
    this.mutations = new WorkflowMutationCoordinator(options);
    const authorization = options.plan.targetAuthorization ? new TargetAuthorizationGuard(options.plan.targetAuthorization) : undefined;
    if (authorization && authorization.plan.targetOrigin !== new URL(options.target).origin) throw new Error("TARGET_AUTHORIZATION_ORIGIN_MISMATCH");
    if (authorization?.plan.bugBounty && !authorization.plan.bugBounty.authenticationPermitted && (options.authProfile || options.authProfileSet)) throw new Error("TARGET_AUTHENTICATION_PROHIBITED");
    this.scopeMatcher = new ScopeMatcher(options.target, options.scope, authorization);
    if (options.recoveryScope) {
      const currentScope = new ScopeMatcher(options.target, options.recoveryScope);
      const originalDecision = this.scopeMatcher.decide.bind(this.scopeMatcher);
      this.scopeMatcher.decide = (url, method) => {
        const original = originalDecision(url, method);
        return original.allowed ? currentScope.decide(url, method) : original;
      };
    }
    this.eventSink = options.eventSink ?? noopScanEventSink;
    this.requestLedger = new ScanRequestLedger(
      options.plan.limits.maxRequests,
      options.plan.limits.cleanupReservedRequests,
      options.plan.limits.rateLimitPerSecond,
      options.plan.limits.concurrency,
      (snapshot, budgetChanged) => {
        this.state.recordRequestBudget(snapshot);
        if (!budgetChanged) return;
        void this.eventSink.emit({
          type: "BUDGET_UPDATED",
          message: `Scan-wide request budget: ${snapshot.totalTransmitted}/${snapshot.maxRequests}; cleanup reserve remaining: ${snapshot.cleanupRemaining}.`,
          metadata: snapshot as unknown as Record<string, unknown>
        });
        void this.options.checkpointReport?.();
      }
    );
    this.state.recordRequestBudget(this.requestLedger.snapshot());
    this.httpClient = this.createHttpClient();
  }

  public createHttpClient(): RequestSafetyBroker {
    if (this.httpClient) {
      return this.httpClient;
    }

    return new RequestSafetyBroker(
      {
        userAgent: this.options.scope.userAgent,
        timeoutMs: this.options.plan.limits.requestTimeoutMs,
        rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
        concurrency: this.options.plan.limits.concurrency,
        bodyPreviewBytes: this.options.plan.limits.bodyPreviewBytes,
        maxResponseBytes: this.options.plan.limits.maxResponseBytes,
        retry: this.options.plan.limits.retry,
        maxRequests: this.options.plan.limits.maxRequests,
        connectionPool: this.connectionPool,
        ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
      },
      this.scopeMatcher,
      (entry) => {
        this.state.recordRequestAudit(entry);
        void this.options.checkpointReport?.();
      },
      this.coordination("SCAN")
    );
  }

  public async runControlledMutation(contract: ControlledMutationContract): Promise<ControlledMutationResult> {
    const attackBudget = (contract.identity?.attempts ?? 0) + 1 + contract.precondition.attempts + contract.impact.attempts + (contract.protectedAction?.attempts ?? 0);
    const cleanupBudget = 1 + contract.rollback.verification.attempts;
    const proofConfigured = this.options.authProfile?.browserBootstrap?.proofCases.some((item) => item.caseId === contract.caseId) === true;
    const browserProofBudget = proofConfigured ? 20 : 0;
    this.scopeMatcher.authorization?.requireRemainingBudget(attackBudget + cleanupBudget + (browserProofBudget * 2));
    const attackTransport = new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: 1,
      bodyPreviewBytes: this.options.plan.limits.bodyPreviewBytes,
      maxResponseBytes: this.options.plan.limits.maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests: attackBudget,
      connectionPool: this.connectionPool,
      controlledMutationEnabled: true,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit(entry), this.coordination("SCAN"));
    const cleanupTransport = this.createWorkflowCleanupHttpClient(cleanupBudget, this.options.plan.limits.maxResponseBytes);
    const proofPolicy = browserPolicyFromSettings(this.moduleSettings("browser-crawler"), this.options.plan.limits, this.options.plan.evidence);
    const protectedProofTransport = proofConfigured ? new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent, timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond, concurrency: 1,
      bodyPreviewBytes: this.options.plan.limits.bodyPreviewBytes, maxResponseBytes: this.options.plan.limits.maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 }, maxRequests: browserProofBudget,
      connectionPool: this.connectionPool,
      controlledMutationEnabled: true, ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit(entry), this.coordination("SCAN")) : undefined;
    const cleanupProofTransport = proofConfigured ? this.createWorkflowCleanupHttpClient(browserProofBudget, this.options.plan.limits.maxResponseBytes) : undefined;
    protectedProofTransport?.setBrowserPolicyEventLimit(proofPolicy.maxPolicyEvents);
    cleanupProofTransport?.setBrowserPolicyEventLimit(proofPolicy.maxPolicyEvents);
    const browserObserver = proofConfigured && this.options.authProfile ? new BrowserProofVerifier({
      authProfile: this.options.authProfile,
      policy: proofPolicy,
      requestBroker: protectedProofTransport!,
      cleanupRequestBroker: cleanupProofTransport!,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {}),
      cleanupSignal: () => this.cleanupSignal(cleanupProofTransport!),
      targetUrl: this.options.target,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      userAgent: this.options.scope.userAgent
    }) : undefined;
    try {
      return await new ControlledMutationExecutor(attackTransport, { journalDirectory: this.mutations.directory, ...(this.options.checkpointReport ? { checkpointReport: this.options.checkpointReport } : {}), cleanupTransport, cleanupSleep: (ms) => this.cleanupWait(cleanupTransport, ms), ...(browserObserver ? { browserObserver } : {}), ...(this.options.plan.targetAuthorization ? { targetAuthorization: this.options.plan.targetAuthorization } : {}) }).execute(contract);
    } finally {
      this.finishCleanup(cleanupTransport);
      if (cleanupProofTransport) this.finishCleanup(cleanupProofTransport);
    }
  }

  /**
   * Creates a sequential, independently bounded broker for an explicitly
   * authorized authentication-lifecycle plan. Raw response material remains in
   * the broker's transient WeakMap analysis channel and is never serialized.
   */
  public createAuthenticationLifecycleHttpClient(maxRequests: number, maxResponseBytes: number): RequestSafetyBroker {
    this.scopeMatcher.authorization?.requireRemainingBudget(maxRequests);
    const fixtureOrigins = [...(this.options.plan.authenticationLifecycle?.fixtures?.providers.flatMap((provider) => [new URL(provider.baseUrl).origin, ...(provider.tokenBaseUrl ? [new URL(provider.tokenBaseUrl).origin] : provider.provider === "FIREBASE" && new URL(provider.baseUrl).hostname === "identitytoolkit.googleapis.com" ? ["https://securetoken.googleapis.com"] : [])]) ?? []), ...(this.options.plan.authenticationLifecycle?.fixtures?.inboxes.flatMap((inbox) => inbox.kind === "LOCAL_HTTP" ? [] : [new URL(inbox.baseUrl).origin]) ?? [])];
    return new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: 1,
      bodyPreviewBytes: maxResponseBytes,
      maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests,
      connectionPool: this.connectionPool,
      allowedPrivateOrigins: fixtureOrigins,
      controlledMutationEnabled: true,
      controlledDeletionEnabled: true,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit({ ...entry, requestedUrl: "redacted://authentication-lifecycle-request", ...(entry.finalUrl ? { finalUrl: "redacted://authentication-lifecycle-response" } : {}), requestHeaders: Object.fromEntries(Object.keys(entry.requestHeaders).map((name) => [name, "<redacted>"])), redirectChain: entry.redirectChain.map((hop) => ({ ...hop, location: "<redacted>" })) }), this.coordination("SCAN"));
  }

  /**
   * Creates an independently bounded transport for explicitly authorized
   * invariant cases. Concurrency is capped by the validated plan; mutations
   * are never retried or redirected by their executor.
   */
  public createBusinessInvariantHttpClient(maxRequests: number, maxResponseBytes: number, maxConcurrency: number): RequestSafetyBroker {
    this.scopeMatcher.authorization?.requireRemainingBudget(maxRequests);
    return new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: Math.max(1, Math.min(4, maxConcurrency)),
      bodyPreviewBytes: maxResponseBytes,
      maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests,
      connectionPool: this.connectionPool,
      controlledMutationEnabled: true,
      controlledDeletionEnabled: true,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit(entry), this.coordination("SCAN"));
  }

  /** Creates a race-only broker whose explicit 2-5 member synchronized groups
   * bypass ordinary pacing as one bounded burst while retaining every other
   * request-safety boundary. */
  public createControlledRaceHttpClient(maxRequests: number, maxResponseBytes: number, maxConcurrency: number): RequestSafetyBroker {
    this.scopeMatcher.authorization?.requireRemainingBudget(maxRequests);
    return new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: Math.max(2, Math.min(5, maxConcurrency)),
      bodyPreviewBytes: maxResponseBytes,
      maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests,
      connectionPool: this.connectionPool,
      controlledMutationEnabled: true,
      controlledDeletionEnabled: true,
      controlledRaceEnabled: true,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit(entry), this.coordination("SCAN"));
  }

  /** Dedicated read/query transport for explicit API and GraphQL matrices. */
  public createApiGraphqlHttpClient(maxRequests: number, maxResponseBytes: number): RequestSafetyBroker {
    return new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: Math.max(1, Math.min(4, this.options.plan.limits.concurrency)),
      bodyPreviewBytes: maxResponseBytes,
      maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests,
      connectionPool: this.connectionPool,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit(entry), this.coordination("SCAN"));
  }

  /** Bounded active-validation transport. All probe families share the
   * scan-wide ledger, disable mutation escalation, redirects, and retries at
   * call sites, and retain raw bodies only through the transient analysis
   * channel. */
  public createActiveVulnerabilityHttpClient(maxRequests: number, maxResponseBytes: number): RequestSafetyBroker {
    this.scopeMatcher.authorization?.requireRemainingBudget(maxRequests);
    return new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: Math.max(1, Math.min(3, this.options.plan.limits.concurrency)),
      bodyPreviewBytes: maxResponseBytes,
      maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests,
      connectionPool: this.connectionPool,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit({
      ...entry,
      requestedUrl: "redacted://active-vulnerability-request",
      ...(entry.finalUrl ? { finalUrl: "redacted://active-vulnerability-response" } : {}),
      requestHeaders: Object.fromEntries(Object.keys(entry.requestHeaders).map((name) => [name, "<redacted>"])),
      redirectChain: entry.redirectChain.map((hop) => ({ ...hop, location: "<redacted>" }))
    }), this.coordination("SCAN"));
  }

  /** Dedicated bounded transport for signed capabilities and protected artifacts.
   * Request-audit locations are replaced wholesale because path segments as well
   * as query values may be capability or object secrets. */
  public createLinkPortalSecurityHttpClient(maxRequests: number, maxResponseBytes: number): RequestSafetyBroker {
    this.scopeMatcher.authorization?.requireRemainingBudget(maxRequests);
    return new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: 1,
      bodyPreviewBytes: maxResponseBytes,
      maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests,
      connectionPool: this.connectionPool,
      controlledMutationEnabled: true,
      controlledDeletionEnabled: true,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit({
      ...entry,
      requestedUrl: "redacted://link-portal-request",
      ...(entry.finalUrl ? { finalUrl: "redacted://link-portal-response" } : {}),
      redirectChain: entry.redirectChain.map((hop) => ({ ...hop, location: "<redacted>" }))
    }), this.coordination("SCAN"));
  }

  /** Sequential controlled transport for webhook, scheduler, and operational
   * endpoints. Audit URLs are replaced because job/event identifiers may be
   * sensitive even when they appear in path segments. */
  public createOperationalEndpointSecurityHttpClient(maxRequests: number, maxResponseBytes: number): RequestSafetyBroker {
    this.scopeMatcher.authorization?.requireRemainingBudget(maxRequests);
    return new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: 1,
      bodyPreviewBytes: maxResponseBytes,
      maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests,
      connectionPool: this.connectionPool,
      controlledMutationEnabled: true,
      controlledDeletionEnabled: true,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit({
      ...entry,
      requestedUrl: "redacted://operational-endpoint-request",
      ...(entry.finalUrl ? { finalUrl: "redacted://operational-endpoint-response" } : {}),
      requestHeaders: Object.fromEntries(Object.keys(entry.requestHeaders).map((name) => [name, "<redacted>"])),
      redirectChain: entry.redirectChain.map((hop) => ({ ...hop, location: "<redacted>" }))
    }), this.coordination("SCAN"));
  }

  /** Dedicated synthetic billing transport. It permits only the planner's
   * bounded fixture mutations/races; audit locations and every request-header
   * value are erased because event, subscription, and provider-test material
   * may use application-specific names. */
  public createBillingEntitlementHttpClient(maxRequests: number, maxResponseBytes: number, maxConcurrency: number): RequestSafetyBroker {
    this.scopeMatcher.authorization?.requireRemainingBudget(maxRequests);
    return new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: Math.max(2, Math.min(5, maxConcurrency)),
      bodyPreviewBytes: maxResponseBytes,
      maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests,
      connectionPool: this.connectionPool,
      controlledMutationEnabled: true,
      controlledDeletionEnabled: true,
      controlledRaceEnabled: true,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit({
      ...entry,
      requestedUrl: "redacted://billing-entitlement-request",
      ...(entry.finalUrl ? { finalUrl: "redacted://billing-entitlement-response" } : {}),
      requestHeaders: Object.fromEntries(Object.keys(entry.requestHeaders).map((name) => [name, "<redacted>"])),
      redirectChain: entry.redirectChain.map((hop) => ({ ...hop, location: "<redacted>" }))
    }), this.coordination("SCAN"));
  }

  public moduleSettings(moduleId: ModuleId): Readonly<ModuleSettings> {
    return this.options.plan.modules.find((modulePlan) => modulePlan.id === moduleId)?.settings ?? {};
  }

  public createWorkflowCleanupHttpClient(maxRequests: number, maxResponseBytes: number, allowedPrivateOrigins: readonly string[] = []): RequestSafetyBroker {
    const window = new CleanupExecution();
    const broker = new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent, timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: Math.min(this.options.plan.limits.rateLimitPerSecond, this.options.recoveryScope?.rateLimitPerSecond ?? this.options.scope.rateLimitPerSecond), concurrency: 1,
      bodyPreviewBytes: maxResponseBytes, maxResponseBytes, maxRequests,
      connectionPool: this.connectionPool,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      controlledMutationEnabled: true, controlledDeletionEnabled: true,
      allowedPrivateOrigins,
      abortSignal: AbortSignal.any([window.signal, this.cancellationCleanup.signal])
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit({ ...entry, requestedUrl: "redacted://workflow-cleanup", ...(entry.finalUrl ? { finalUrl: "redacted://workflow-cleanup" } : {}), requestHeaders: Object.fromEntries(Object.keys(entry.requestHeaders).map((key) => [key, "<redacted>"])), redirectChain: entry.redirectChain.map((hop) => ({ ...hop, location: "<redacted>" })) }), this.coordination("CLEANUP"));
    this.cleanupWindows.set(broker, window);
    const send = broker.send.bind(broker);
    broker.send = async (request) => {
      window.start();
      if (!this.cleanupAnnounced.has(broker)) {
        this.cleanupAnnounced.add(broker);
        await this.eventSink.emit({ type: "CLEANUP_STARTED", message: "Cancellation-safe cleanup or restoration verification started.", metadata: { timeoutMs: 120_000 } });
      }
      await this.options.checkpointReport?.();
      return send(request);
    };
    return broker;
  }

  public cleanupSignal(broker: RequestSafetyBroker): AbortSignal {
    const window = this.cleanupWindows.get(broker);
    if (!window) throw new Error("CLEANUP_TRANSPORT_REQUIRED");
    return AbortSignal.any([window.start(), this.cancellationCleanup.signal]);
  }

  private coordination(lane: RequestLedgerLane) {
    return { ledger: this.requestLedger, lane } as const;
  }

  public async cleanupWait(broker: RequestSafetyBroker, milliseconds: number): Promise<void> {
    const { setTimeout } = await import("node:timers/promises");
    await setTimeout(milliseconds, undefined, { signal: this.cleanupSignal(broker) });
  }

  public finishCleanup(broker: RequestSafetyBroker): void {
    this.cleanupWindows.get(broker)?.dispose();
    this.cleanupWindows.delete(broker);
  }

  public async dispose(): Promise<void> {
    this.finishCaseCleanup();
    this.cancellationCleanup.dispose();
    await this.connectionPool.close();
  }

  public transportDiagnostics() { return this.connectionPool.diagnostics(); }

  public finishCaseCleanup(): void {
    for (const window of this.cleanupWindows.values()) window.dispose();
    this.cleanupWindows.clear();
  }
}
