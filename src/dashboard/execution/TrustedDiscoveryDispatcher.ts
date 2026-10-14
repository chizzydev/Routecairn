import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { types as nativeTypes } from "node:util";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { assertRegisteredTargetScope } from "./RegisteredTargetScope.js";
import {
  planAdaptiveDiscoveryCandidates,
  validateAdaptiveDiscoveryCandidate
} from "./AdaptiveDiscoveryCandidatePlanner.js";
import { projectAdaptiveObservedInputs } from "./AdaptiveObservedInputProjection.js";
import { adaptiveHttpUrl } from "./AdaptiveEvidenceSafety.js";
import {
  discoveryDeny,
  TrustedDiscoveryDenial,
  TrustedDiscoverySource,
  discoveryDigest,
  type TrustedDiscoverySnapshot,
  type TrustedDiscoveryActor
} from "./TrustedDiscoverySource.js";
import {
  bindTrustedDiscoveryOperation,
  opaqueDiscoveryObject,
  operationBelongsTo,
  discoveryFacts,
  consumeTrustedDiscoveryConsent,
  trustedDiscoveryContextState,
  type TrustedDiscoveryFacts
} from "./TrustedDiscoveryBinding.js";
export const trustedDiscoveryOperationalStatus = Object.freeze({
  registered: false,
  defaultOff: true,
  operatorWorkflow: "OPERATOR_UI_AND_DURABLE_CONSENT=NG5B2_UNIMPLEMENTED",
  validation: "OWNED_FIXTURE_ONLY"
});
/** These callbacks are injected ONLY by the privileged native host. They do not implement login.
 * The host must verify opaque receipts; constructor IDs/booleans/public candidates provide no authority. */
export interface OwnedFixtureDiscoveryHost {
  verifyActor(receipt: unknown): TrustedDiscoveryActor | undefined;
  verifyConsent(
    receipt: unknown,
    facts: { route: string; targetGeneration: string; sourceDigest: string; targetId: string }
  ):
    | {
        organizationId: string;
        userId: string;
        targetId: string;
        route: string;
        effect: string;
        sourceDigest: string;
        targetGeneration: string;
        expiresAt: number;
      }
    | undefined;
}
interface Review {
  snapshot: TrustedDiscoverySnapshot;
  actor: TrustedDiscoveryActor;
  actorReceipt: unknown;
  url: string;
  contextGeneration: string;
  consentUsed: boolean;
}
export class TrustedDiscoveryDispatcher {
  private readonly source: TrustedDiscoverySource;
  private readonly broker: RequestSafetyBroker;
  private readonly reviews = new WeakMap<object, Review>();
  private readonly contextState: ReturnType<typeof trustedDiscoveryContextState>;
  private reviewsCount = 0;
  private readonly clock: () => number;
  public constructor(
    private readonly options: {
      database: DashboardDatabase;
      reportRoot: string;
      context: ScanContext;
      host?: OwnedFixtureDiscoveryHost;
      /** Owned test harness native peer only: same actual ScanContext scope and SCAN ledger. */
      broker?: RequestSafetyBroker;
      clock?: () => number;
    }
  ) {
    this.source = new TrustedDiscoverySource(options.database, options.reportRoot);
    this.broker = options.broker ?? options.context.httpClient;
    this.contextState = trustedDiscoveryContextState(options.context);
    this.clock = options.clock ?? Date.now;
  }
  public review(input: unknown, actorReceipt: unknown): { result: TrustedDiscoveryFacts; review?: object } {
    try {
      if (
        !this.options.host ||
        typeof this.options.host.verifyActor !== "function" ||
        typeof this.options.host.verifyConsent !== "function"
      )
        discoveryDeny("DENIED_OPERATOR_BINDING");
      const actor = this.options.host.verifyActor(actorReceipt);
      if (!actor) discoveryDeny("DENIED_OPERATOR_BINDING");
      const fields = this.selector(input);
      if (++this.reviewsCount > 64) discoveryDeny("DENIED_CAPACITY");
      const snapshot = this.source.capture(fields.scanId, actor);
      this.assertContext(snapshot);
      const projected = projectAdaptiveObservedInputs(snapshot.report),
        plan = planAdaptiveDiscoveryCandidates(snapshot.report);
      if (
        projected.diagnostics.length ||
        plan.diagnostics.length ||
        plan.upstreamDiagnostics.length ||
        plan.accountedObservations !== projected.observations.length ||
        plan.accountingLedger.length !== projected.observations.length ||
        plan.accountingLedger.some((v) => v.state !== "CANDIDATE")
      )
        discoveryDeny("DENIED_SOURCE_STALE");
      const matches = plan.candidates.filter((c) => c.candidateId === fields.candidateId);
      if (matches.length !== 1) discoveryDeny("DENIED_SOURCE_STALE");
      const candidate = matches[0]!;
      if (
        fields.candidate !== undefined &&
        (!validateAdaptiveDiscoveryCandidate(fields.candidate, snapshot.report) ||
          (fields.candidate as { candidateId?: unknown }).candidateId !== candidate.candidateId)
      )
        discoveryDeny("DENIED_SOURCE_STALE");
      if (
        candidate.method !== "GET" ||
        candidate.originRelation !== "PRIMARY_TARGET" ||
        candidate.targetOrigin !== snapshot.origin ||
        candidate.reportCompleteness !== "COMPLETED_REPORTED" ||
        candidate.upstreamEvidenceIncomplete ||
        candidate.alreadyObservedExchange ||
        candidate.nextStep !== "REVIEW_FOR_POTENTIAL_PROBE" ||
        candidate.sourceReferences.length !== 1
      )
        discoveryDeny("DENIED_DUPLICATE");
      const ref = candidate.sourceReferences[0]!;
      if (ref.producer !== "API_MAPPER" || ref.disposition !== "API_DISCOVERY_CANDIDATE")
        discoveryDeny("DENIED_SOURCE_STALE");
      const observations = projected.observations.filter(
        (v) => v.producer === ref.producer && v.sourceIndex === ref.sourceIndex && v.observationId === ref.observationId
      );
      if (
        observations.length !== 1 ||
        observations[0]!.method !== "GET" ||
        observations[0]!.routeOrdinal !== candidate.routeOrdinal
      )
        discoveryDeny("DENIED_SOURCE_STALE");
      const original = snapshot.report.apiMapper?.endpoints[ref.sourceIndex];
      if (
        !original ||
        original.method !== "GET" ||
        original.hasObjectId ||
        (original.authRelevance && original.authRelevance !== "low")
      )
        discoveryDeny("DENIED_SCOPE");
      const url = this.route(original.endpoint, snapshot.origin);
      this.assertUnattemptedGet(url);
      if (
        snapshot.report.apiMapper!.endpoints.filter((e) => adaptiveHttpUrl(e.endpoint, snapshot.origin)?.href === url)
          .length !== 1
      )
        discoveryDeny("DENIED_DUPLICATE");
      if (
        snapshot.report.responses.some(
          (r) => r.method === "GET" && adaptiveHttpUrl(r.requestedUrl, snapshot.origin)?.href === url
        ) ||
        snapshot.report.apiProbe?.endpointsReviewed.some(
          (r) => adaptiveHttpUrl(r.endpoint, snapshot.origin)?.href === url && r.methodsTested.includes("GET")
        ) ||
        snapshot.report.discoveredUrls?.some(
          (r) => r.method === "GET" && adaptiveHttpUrl(r.url, snapshot.origin)?.href === url
        )
      )
        discoveryDeny("DENIED_DUPLICATE");
      if (
        !new ScopeMatcher(snapshot.origin, snapshot.scope).decide(url, "GET").allowed ||
        !this.options.context.scopeMatcher.decide(url, "GET").allowed
      )
        discoveryDeny("DENIED_SCOPE");
      const key = discoveryDigest(snapshot.origin + "\n" + url);
      if (this.contextState.routes.has(key)) discoveryDeny("DENIED_DUPLICATE");
      this.contextState.routes.add(key);
      const review = opaqueDiscoveryObject();
      this.reviews.set(review, {
        snapshot,
        actor,
        actorReceipt,
        url,
        contextGeneration: this.contextGeneration(),
        consentUsed: false
      });
      return { result: discoveryFacts("SELECTED_FOR_REVIEW"), review };
    } catch (error) {
      return { result: this.denial(error) };
    }
  }
  public consent(token: unknown, receipt: unknown): { result: TrustedDiscoveryFacts; operation?: object } {
    try {
      const review = token && typeof token === "object" ? this.reviews.get(token) : undefined;
      if (!review || review.consentUsed) discoveryDeny("DENIED_OPERATOR_BINDING");
      this.verifyReview(review);
      const consent = this.options.host!.verifyConsent(receipt, this.consentFacts(review));
      if (!consent) discoveryDeny("DENIED_OPERATOR_BINDING");
      if (consent.effect !== "NON_MUTATING") discoveryDeny("DENIED_EFFECT_UNKNOWN");
      this.assertConsent(review, consent);
      consumeTrustedDiscoveryConsent(receipt);
      review.consentUsed = true;
      const originalConsent = JSON.stringify(consent);
      const operation = bindTrustedDiscoveryOperation({
        broker: this.broker,
        owner: this,
        ledger: this.options.context.requestLedger,
        scope: this.options.context.scopeMatcher,
        url: review.url,
        attempted: false,
        initiated: false,
        consumeAttempt: () => {
          if (this.contextState.attempted) discoveryDeny("DENIED_CAPACITY");
          this.contextState.attempted = true;
        },
        verify: () => {
          this.verifyReview(review);
          const current = this.options.host!.verifyConsent(receipt, this.consentFacts(review));
          if (!current || JSON.stringify(current) !== originalConsent) discoveryDeny("DENIED_OPERATOR_BINDING");
          // Native receipt verification may perform synchronous control-plane work.
          // Re-read rows/bytes after it, before the final deadline and broker commit.
          this.verifyReview(review);
          this.assertConsent(review, current); // Clock check AFTER bounded synchronous row/file IO.
        }
      });
      return { result: discoveryFacts("SELECTED_FOR_REVIEW"), operation };
    } catch (error) {
      return { result: this.denial(error) };
    }
  }
  public async execute(operation: unknown): Promise<TrustedDiscoveryFacts> {
    if (!operationBelongsTo(operation, this)) return discoveryFacts("DENIED_OPERATOR_BINDING");
    return this.broker.dispatchTrustedDiscoveryGet(operation);
  }
  private verifyReview(review: Review): void {
    this.assertUnattemptedGet(review.url);
    const current = this.options.host?.verifyActor(review.actorReceipt);
    if (!current || current.organizationId !== review.actor.organizationId || current.userId !== review.actor.userId)
      discoveryDeny("DENIED_OPERATOR_BINDING");
    this.source.assertCurrent(review.snapshot, current);
    this.assertContext(review.snapshot);
    if (this.contextGeneration() !== review.contextGeneration) discoveryDeny("DENIED_SCOPE");
  }
  private consentFacts(review: Review) {
    return {
      route: review.url,
      sourceDigest: review.snapshot.digest,
      targetGeneration: review.snapshot.targetGeneration,
      targetId: review.snapshot.targetId
    };
  }
  private assertUnattemptedGet(url: string): void {
    // Native keyed intent history is authoritative for pending/cache/error GETs.
    // Completed context audit is an additional refusal signal, never permission.
    if (this.broker.hasTrustedDiscoveryGetConflict(url)) discoveryDeny("DENIED_DUPLICATE");
    for (const audit of this.options.context.state.getRequestAudit()) {
      if (audit.method !== "GET" || !["sent", "duplicate-skipped"].includes(audit.outcome)) continue;
      for (const value of [audit.requestedUrl, audit.finalUrl]) {
        try {
          if (value && normalizeUrl(value) === url) discoveryDeny("DENIED_DUPLICATE");
        } catch (error) {
          if (error instanceof TrustedDiscoveryDenial) throw error;
        }
      }
    }
  }
  private assertConsent(
    review: Review,
    consent: NonNullable<ReturnType<OwnedFixtureDiscoveryHost["verifyConsent"]>>
  ): void {
    if (
      consent.organizationId !== review.actor.organizationId ||
      consent.userId !== review.actor.userId ||
      consent.targetId !== review.snapshot.targetId ||
      consent.route !== review.url ||
      consent.sourceDigest !== review.snapshot.digest ||
      consent.targetGeneration !== review.snapshot.targetGeneration ||
      !Number.isFinite(consent.expiresAt) ||
      this.clock() >= consent.expiresAt ||
      consent.expiresAt - this.clock() > 60_000 ||
      consent.effect !== "NON_MUTATING"
    )
      discoveryDeny("DENIED_OPERATOR_BINDING");
  }
  private assertContext(snapshot: TrustedDiscoverySnapshot): void {
    const context = this.options.context,
      options = context.options,
      limits = options.plan.limits;
    if (
      !(context instanceof ScanContext) ||
      !(this.broker instanceof RequestSafetyBroker) ||
      options.eventSink ||
      options.checkpointReport
    )
      discoveryDeny("DENIED_SCOPE");
    if (
      new URL(options.target).origin !== snapshot.origin ||
      options.authProfile ||
      options.authProfileSet ||
      !context.scopeMatcher.authorization ||
      context.scopeMatcher.authorization.plan.mode !== "INTERNAL_STAGING" ||
      context.scopeMatcher.authorization.plan.targetOrigin !== snapshot.origin ||
      options.scope.userAgent !== "RouteCairn/0.1" ||
      options.scope.allowedMethods.some((m) => m !== "GET") ||
      limits.rateLimitPerSecond > 1 ||
      limits.concurrency !== 1 ||
      limits.maxRequests > 8 ||
      limits.maxRequests <= limits.cleanupReservedRequests ||
      limits.maxResponseBytes > 65536 ||
      options.config.transport.http2Enabled ||
      !options.scope.sameOriginOnly ||
      options.scope.includeSubdomains
    )
      discoveryDeny("DENIED_SCOPE");
    try {
      assertRegisteredTargetScope(options.scope, snapshot.scope, limits);
    } catch {
      discoveryDeny("DENIED_SCOPE");
    }
  }
  private contextGeneration(): string {
    return discoveryDigest(
      JSON.stringify({
        target: this.options.context.options.target,
        scope: this.options.context.options.scope,
        limits: this.options.context.options.plan.limits,
        authorization: this.options.context.scopeMatcher.authorization?.plan
      })
    );
  }
  private selector(value: unknown): { scanId: string; candidateId: string; candidate?: unknown } {
    if (!isPlainDiscoverySelection(value)) discoveryDeny("DENIED_SOURCE_STALE");
    if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype)
      discoveryDeny("DENIED_SOURCE_STALE");
    const keys = Reflect.ownKeys(value);
    if (keys.some((k) => typeof k !== "string" || !["scanId", "candidateId", "candidate"].includes(k)))
      discoveryDeny("DENIED_SOURCE_STALE");
    const fields: Record<string, unknown> = {};
    for (const key of keys) {
      const d = Object.getOwnPropertyDescriptor(value, key);
      if (!d || !("value" in d)) discoveryDeny("DENIED_SOURCE_STALE");
      fields[String(key)] = d.value;
    }
    if (
      typeof fields.scanId !== "string" ||
      fields.scanId.length > 128 ||
      typeof fields.candidateId !== "string" ||
      !/^[a-f0-9]{64}$/.test(fields.candidateId)
    )
      discoveryDeny("DENIED_SOURCE_STALE");
    return fields as { scanId: string; candidateId: string; candidate?: unknown };
  }
  private route(raw: string, origin: string): string {
    if (typeof raw !== "string" || raw.length > 512 || /[%\\?#@]/.test(raw) || /(?:^|\/)\.\.?(?:\/|$)/.test(raw))
      discoveryDeny("DENIED_SCOPE");
    const url = adaptiveHttpUrl(raw, origin);
    if (
      !url ||
      url.origin !== origin ||
      url.search ||
      url.hash ||
      url.pathname.length > 160 ||
      url.pathname
        .split("/")
        .filter(Boolean)
        .some(
          (segment) =>
            !/^[a-z][a-z_-]{0,31}$/.test(segment) ||
            segment
              .split(/[-_]/)
              .some((word) =>
                /^(?:logout|admin|delete|reset|purchase|trigger|action|callback|token|signed|sign|invite|secret|session|payment|cart|remove|update|create|withdraw|restore|transfer)$/.test(
                  word
                )
              )
        )
    )
      discoveryDeny("DENIED_SCOPE");
    return url.href;
  }
  private denial(error: unknown): TrustedDiscoveryFacts {
    return discoveryFacts(error instanceof TrustedDiscoveryDenial ? error.code : "DENIED_SOURCE_STALE");
  }
}

/** Preflight includes proxies before reflective operations. No getter/toJSON is evaluated. */
function isPlainDiscoverySelection(input: unknown): boolean {
  let nodes = 0;
  const ancestors = new Set<object>();
  const walk = (value: unknown, depth: number): boolean => {
    if (++nodes > 1500 || depth > 8) return false;
    if (value === null || typeof value === "boolean") return true;
    if (typeof value === "string") return value.length <= 1000;
    if (typeof value === "number") return Number.isFinite(value);
    if (
      !value ||
      typeof value !== "object" ||
      nativeTypes.isProxy(value) ||
      ancestors.has(value) ||
      (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype)
    )
      return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length > 70) return false;
    ancestors.add(value);
    for (const key of keys) {
      if (typeof key !== "string") return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !walk(descriptor.value, depth + 1)) return false;
    }
    ancestors.delete(value);
    return true;
  };
  try {
    return walk(input, 0);
  } catch {
    return false;
  }
}
