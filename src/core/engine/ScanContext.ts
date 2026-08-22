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

export interface ScanContextOptions {
  target: string;
  scope: RouteCairnScope;
  config: RouteCairnConfig;
  plan: ResolvedScanPlan;
  outputDir: string;
  authProfile?: AuthProfile;
  authProfileSet?: AuthProfileSet;
  eventSink?: ScanEventSink;
  abortSignal?: AbortSignal;
  controlledMutationContracts?: readonly import("../offensive/ControlledMutationTypes.js").ControlledMutationContract[];
}

export class ScanContext {
  public readonly scopeMatcher: ScopeMatcher;
  public readonly httpClient: RequestSafetyBroker;
  public readonly state = new ScanState();
  public readonly eventSink: ScanEventSink;

  public constructor(public readonly options: ScanContextOptions) {
    this.scopeMatcher = new ScopeMatcher(options.target, options.scope);
    this.eventSink = options.eventSink ?? noopScanEventSink;
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
        ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
      },
      this.scopeMatcher,
      (entry) => this.state.recordRequestAudit(entry)
    );
  }

  public async runControlledMutation(contract: ControlledMutationContract): Promise<ControlledMutationResult> {
    const attackTransport = new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: 1,
      bodyPreviewBytes: this.options.plan.limits.bodyPreviewBytes,
      maxResponseBytes: this.options.plan.limits.maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests: this.options.plan.privilegeMutationTesting?.maxRequests ?? 1,
      controlledMutationEnabled: true,
      ...(this.options.abortSignal ? { abortSignal: this.options.abortSignal } : {})
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit(entry));
    const cleanupTransport = new RequestSafetyBroker({
      userAgent: this.options.scope.userAgent,
      timeoutMs: this.options.plan.limits.requestTimeoutMs,
      rateLimitPerSecond: this.options.plan.limits.rateLimitPerSecond,
      concurrency: 1,
      bodyPreviewBytes: this.options.plan.limits.bodyPreviewBytes,
      maxResponseBytes: this.options.plan.limits.maxResponseBytes,
      retry: { ...this.options.plan.limits.retry, maxAttempts: 1 },
      maxRequests: this.options.plan.privilegeMutationTesting?.maxRequests ?? 1,
      controlledMutationEnabled: true
    }, this.scopeMatcher, (entry) => this.state.recordRequestAudit(entry));
    return new ControlledMutationExecutor(attackTransport, { journalDirectory: this.options.outputDir, cleanupTransport }).execute(contract);
  }

  public moduleSettings(moduleId: ModuleId): Readonly<ModuleSettings> {
    return this.options.plan.modules.find((modulePlan) => modulePlan.id === moduleId)?.settings ?? {};
  }
}
