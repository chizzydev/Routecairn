import type { RouteCairnConfig, RouteCairnScope } from "../../config/ConfigSchema.js";
import type { AuthProfile } from "../auth/AuthProfile.js";
import type { AuthProfileSet } from "../auth/AuthProfileSet.js";
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

  public moduleSettings(moduleId: ModuleId): Readonly<ModuleSettings> {
    return this.options.plan.modules.find((modulePlan) => modulePlan.id === moduleId)?.settings ?? {};
  }
}
