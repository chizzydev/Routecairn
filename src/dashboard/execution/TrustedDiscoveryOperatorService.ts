import { withTrustedDiscoveryDatabaseDeadline } from "./TrustedDiscoveryDatabaseDeadline.js";
import { randomBytes, randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import { types } from "node:util";
import { controlPlaneConfigFromEnv } from "../../controlPlane/ControlPlaneConfig.js";
import { TrustedDiscoveryWitness } from "./TrustedDiscoveryWitness.js";
import { TrustedDiscoveryPrivateRoot } from "./TrustedDiscoveryPrivateRoot.js";
import { opaqueDiscoveryObject, type TrustedDiscoveryFacts } from "./TrustedDiscoveryBinding.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import { ScanPlanner } from "../../core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../core/engine/ScanOrchestrator.js";
import { defaultConfig } from "../../config/defaults.js";
import type { ServerSessionManager } from "../auth/ServerSession.js";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import { OrganizationService } from "../operations/OrganizationService.js";
import { TrustedDiscoveryDispatcher, type OwnedFixtureDiscoveryHost } from "./TrustedDiscoveryDispatcher.js";
import {
  TrustedDiscoverySource,
  type TrustedDiscoveryActor,
  type TrustedDiscoverySnapshot
} from "./TrustedDiscoverySource.js";
import { planAdaptiveDiscoveryCandidates } from "./AdaptiveDiscoveryCandidatePlanner.js";
import {
  TrustedDiscoveryReviewStore,
  TrustedDiscoveryStageAError,
  type DiscoveryAttemptDescriptor
} from "./TrustedDiscoveryReviewStore.js";

const id = z.string().uuid();
export const trustedDiscoveryReviewSchema = z
  .object({ scanId: id, candidateId: z.string().regex(/^[a-f0-9]{64}$/) })
  .strict();
const exactReviewSchema = z
  .object({
    reviewId: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    scanId: id,
    candidateId: z.string().regex(/^[a-f0-9]{64}$/),
    targetId: id,
    routeLabel: z.string().max(160),
    method: z.literal("GET"),
    effect: z.literal("NON_MUTATING"),
    reviewDigest: z.string().regex(/^[a-f0-9]{64}$/),
    expiresAt: z.string().datetime()
  })
  .strict();
export const trustedDiscoveryPreconsentSchema = exactReviewSchema
  .extend({ confirmation: z.literal("I_CONFIRM_ONE_ANONYMOUS_NON_MUTATING_LOCAL_GET") })
  .strict();
type PublicReview = z.infer<typeof exactReviewSchema>;
type ExecutionResult = Omit<TrustedDiscoveryFacts, "code"> & {
  code: TrustedDiscoveryFacts["code"] | "DISABLED";
  status: string;
  cleanup?: "FAILED" | "CONFIRMED" | "NOT_REQUIRED";
  outcomePersistence?: "COMMITTED" | "UNKNOWN";
};
interface PendingReview {
  id: string;
  actor: TrustedDiscoveryActor;
  sessionId: string;
  authority: object;
  snapshot: TrustedDiscoverySnapshot;
  producerGeneration: string;
  route: string;
  publicReview: PublicReview;
  context: ScanContext;
  controller: AbortController;
  nativeReview: object;
  dispatcher?: TrustedDiscoveryDispatcher;
  privateRoot?: TrustedDiscoveryPrivateRoot;
  consentReceipt?: object;
  operation?: object;
  reservation?: DiscoveryAttemptDescriptor;
  executing?: boolean;
  removed?: boolean;
  possiblyAttempted?: boolean;
}
export const trustedDiscoveryStageAFacts = (code: string) => ({
  code,
  status: "NOT_EXECUTED" as const,
  attempted: 0,
  initiated: 0,
  observed: 0,
  executionAuthority: "NONE" as const
});

/** Dashboard instances remain preview-only. Native fixture peers require a separately
 * provisioned independent witness; no public execution route is registered. */
export class TrustedDiscoveryOperatorService {
  private readonly source: TrustedDiscoverySource;
  private readonly store: TrustedDiscoveryReviewStore;
  private readonly organizations: OrganizationService;
  private readonly pending = new Map<string, PendingReview>();
  private readonly disposals = new Set<Promise<void>>();
  private readonly invalidations = new Map<string, string>();
  private readonly timer: NodeJS.Timeout;
  private closed = false;
  private disposalFailed = false;
  private custodyFailed = false;
  private outcomeFailureAfterInitiation = false;
  private readonly inFlight = new Set<Promise<TrustedDiscoveryFacts>>();
  public constructor(
    private readonly database: DashboardDatabase,
    private readonly paths: DashboardPaths,
    private readonly sessions: ServerSessionManager,
    private readonly witness?: TrustedDiscoveryWitness
  ) {
    if (witness !== undefined && controlPlaneConfigFromEnv().mode !== "local")
      throw new Error("TRUSTED_DISCOVERY_REQUIRES_LOCAL_CONTROL_PLANE");
    this.source = new TrustedDiscoverySource(database, paths.reportsDir);
    this.store = new TrustedDiscoveryReviewStore(database, join(paths.dataDir, "keys", "trusted-discovery-review.key"));
    this.organizations = new OrganizationService(database);
    try {
      if (witness !== undefined && !TrustedDiscoveryWitness.isNative(witness))
        throw new Error("TRUSTED_DISCOVERY_NATIVE_WITNESS_REQUIRED");
      witness?.assertConsistent(database, this.store);
    } catch (error) {
      this.store.dispose();
      throw error;
    }
    this.timer = setInterval(() => this.invalidateStale(), 1000);
    this.timer.unref();
  }
  public async review(
    input: z.infer<typeof trustedDiscoveryReviewSchema>,
    authority: object,
    organizationId: string
  ): Promise<ReturnType<typeof trustedDiscoveryStageAFacts> & { review: PublicReview }> {
    this.invalidateExpired();
    if (this.closed || this.disposalFailed || this.custodyFailed || this.pending.size >= 64)
      throw new TrustedDiscoveryStageAError("DENIED_CAPACITY");
    const createdAt = Date.now(),
      expiresAt = createdAt + 60_000;
    let pending: PendingReview | undefined;
    try {
      withTrustedDiscoveryDatabaseDeadline(this.database, () =>
        this.database.db
          .transaction(() => {
            const actor = this.actor(authority, organizationId),
              native = this.sessions.revalidateTrustedDiscoverySession(authority);
            if (
              !this.database.db
                .prepare("SELECT 1 FROM scans WHERE id=? AND organization_id=?")
                .get(input.scanId, organizationId)
            )
              throw new TrustedDiscoveryStageAError("DENIED_AUTHORITY", 403);
            const snapshot = this.source.capture(input.scanId, actor);
            if (this.witness) {
              this.witness.assertConsistent(this.database, this.store);
              if (snapshot.origin !== this.witness.fixtureOrigin) throw new TrustedDiscoveryStageAError("DENIED_SCOPE");
            }
            const producerGeneration = this.producerGeneration(snapshot.scanId);
            const controller = new AbortController();
            // Stage A remains the original non-executable preview. Only the
            // separately anchored Stage B host allocates disposable execution IO.
            const privateRoot = this.witness ? new TrustedDiscoveryPrivateRoot(this.paths.dataDir) : undefined;
            let context: ScanContext;
            try {
              context = this.createContext(snapshot, controller, privateRoot);
            } catch (error) {
              privateRoot?.dispose();
              throw error;
            }
            // Keep constructed contexts tracked even if native dispatcher or persistence denies.
            pending = {
              id: randomUUID(),
              actor,
              sessionId: native.sessionId,
              authority,
              snapshot,
              producerGeneration,
              route: "",
              publicReview: undefined!,
              context,
              controller,
              nativeReview: undefined!,
              ...(privateRoot ? { privateRoot } : {})
            };
            const ownedPending = pending;
            const host: OwnedFixtureDiscoveryHost = {
              verifyActor: (receipt) => (receipt === authority ? this.actor(authority, organizationId) : undefined),
              verifyConsent: (receipt, facts) => {
                if (!this.witness || !ownedPending.executing || receipt !== ownedPending.consentReceipt)
                  return undefined;
                this.verify(ownedPending, ownedPending.authority, organizationId);
                if (
                  facts.route !== ownedPending.route ||
                  facts.sourceDigest !== ownedPending.snapshot.digest ||
                  facts.targetGeneration !== ownedPending.snapshot.targetGeneration ||
                  facts.targetId !== ownedPending.snapshot.targetId
                )
                  return undefined;
                return {
                  organizationId,
                  userId: actor.userId,
                  targetId: snapshot.targetId,
                  route: ownedPending.route,
                  effect: "NON_MUTATING",
                  sourceDigest: snapshot.digest,
                  targetGeneration: snapshot.targetGeneration,
                  expiresAt
                };
              }
            };
            pending.dispatcher = new TrustedDiscoveryDispatcher({
              database: this.database,
              reportRoot: this.paths.reportsDir,
              context,
              host
            });
            const selected = pending.dispatcher.review(input, authority);
            if (!selected.review)
              throw new TrustedDiscoveryStageAError(
                selected.result.code === "DENIED_SCOPE" ? "DENIED_SCOPE" : "DENIED_SOURCE"
              );
            pending.nativeReview = selected.review;
            const candidate = planAdaptiveDiscoveryCandidates(snapshot.report).candidates.find(
              (v) => v.candidateId === input.candidateId
            )!;
            pending.route = new URL(
              snapshot.report.apiMapper!.endpoints[candidate.sourceReferences[0]!.sourceIndex]!.endpoint,
              snapshot.origin
            ).href;
            if (this.store.hasAttempt(actor, snapshot.targetId, pending.route))
              throw new TrustedDiscoveryStageAError("DENIED_DUPLICATE");
            const reviewId = randomBytes(32).toString("base64url");
            const reviewDigest = this.store.hash("public-review", [
              pending.id,
              native.sessionId,
              actor.organizationId,
              actor.userId,
              input.scanId,
              input.candidateId,
              snapshot.targetId,
              pending.route,
              snapshot.digest,
              snapshot.generation,
              pending.producerGeneration,
              String(expiresAt)
            ]);
            pending.publicReview = {
              reviewId,
              scanId: input.scanId,
              candidateId: input.candidateId,
              targetId: snapshot.targetId,
              routeLabel: new URL(pending.route).pathname,
              method: "GET",
              effect: "NON_MUTATING",
              reviewDigest,
              expiresAt: new Date(expiresAt).toISOString()
            };
            this.verify(pending, authority, organizationId);
            this.store.save({
              id: pending.id,
              actor,
              sessionId: native.sessionId,
              snapshot: {
                ...snapshot,
                generation: this.store.hash("source-with-producer", [snapshot.generation, pending.producerGeneration])
              },
              candidateId: input.candidateId,
              route: pending.route,
              createdAt,
              expiresAt,
              reviewDigest
            });
            this.verify(pending, authority, organizationId);
          })
          .immediate()
      );
      this.pending.set(pending!.publicReview.reviewId, pending!);
      return { ...trustedDiscoveryStageAFacts("REVIEWED"), review: { ...pending!.publicReview } };
    } catch (error) {
      if (pending) this.remove(pending);
      else this.sessions.releaseTrustedDiscoverySession(authority);
      throw error;
    }
  }
  /** Privileged in-process fixture seam ONLY. Stage A history and public lookup
   * fields never mint tokens; the original pending native review is mandatory. */
  public async executeFresh(input: unknown, authority: object, organizationId: string): Promise<ExecutionResult> {
    const empty = (code: TrustedDiscoveryFacts["code"]) => ({
      code,
      status: "DENIED",
      attempted: 0,
      initiated: 0,
      responseObserved: 0,
      auditEvents: 0,
      scanReserved: 0,
      assessment: "NOT_ASSESSED" as const
    });
    // Preserve fixed result typing without treating public codes as capabilities.
    if (!this.witness) {
      this.sessions.releaseTrustedDiscoverySession(authority);
      return { ...empty("DENIED_OPERATOR_BINDING"), code: "DISABLED", status: "DISABLED" };
    }
    let pending: PendingReview | undefined;
    let result: TrustedDiscoveryFacts | undefined;
    let published: ExecutionResult | undefined;
    try {
      if (this.closed || this.disposalFailed || this.custodyFailed)
        throw new TrustedDiscoveryStageAError("UNAVAILABLE");
      if (
        !input ||
        typeof input !== "object" ||
        types.isProxy(input) ||
        Object.getPrototypeOf(input) !== Object.prototype ||
        Reflect.ownKeys(input).some(
          (key) => typeof key !== "string" || !Object.hasOwn(Object.getOwnPropertyDescriptor(input, key)!, "value")
        )
      )
        throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
      const exact = trustedDiscoveryPreconsentSchema.parse(input);
      const actor = this.actor(authority, organizationId),
        session = this.sessions.revalidateTrustedDiscoverySession(authority);
      const selected = this.pending.get(exact.reviewId);
      if (
        !selected ||
        selected.executing ||
        selected.sessionId !== session.sessionId ||
        selected.actor.userId !== actor.userId ||
        selected.actor.organizationId !== organizationId
      )
        throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
      pending = selected;
      if (
        Object.keys(pending.publicReview).some(
          (key) => exact[key as keyof PublicReview] !== pending!.publicReview[key as keyof PublicReview]
        )
      )
        throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
      this.verify(pending, authority, organizationId);
      pending.executing = true;
      pending.consentReceipt = opaqueDiscoveryObject();
      const consented = pending.dispatcher!.consent(pending.nativeReview, pending.consentReceipt);
      if (!consented.operation) throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
      pending.operation = consented.operation;
      const original = pending;
      withTrustedDiscoveryDatabaseDeadline(this.database, () =>
        this.database.db
          .transaction(() => {
            this.verify(original, authority, organizationId);
            this.store.preconsent(original.id, original.actor, original.sessionId);
            const descriptor = this.store.attemptDescriptor(original.id);
            // Independent witness is irreversibly spent BEFORE main tombstone commit.
            original.possiblyAttempted = true;
            this.witness!.spend(this.database, this.store, descriptor);
            if (!this.store.reserveFutureAttempt(original.id))
              throw new TrustedDiscoveryStageAError("DENIED_DUPLICATE");
            original.reservation = descriptor;
            this.verify(original, authority, organizationId);
          })
          .immediate()
      );
      // Covers commit time too; the same checks run again through native host at
      // onRequestStart AFTER queue/rate/DNS. No broker bypass, retry or refund.
      this.verify(pending, authority, organizationId);
      const dispatch = pending.dispatcher!.execute(pending.operation);
      this.inFlight.add(dispatch);
      try {
        result = await dispatch;
      } finally {
        this.inFlight.delete(dispatch);
      }
      try {
        this.witness.recordOutcome(this.database, this.store, pending.id, result);
      } catch {
        // Custody uncertainty blocks new native authority regardless of wire.
        // It is not a failed resource disposal. Pre-initiation denial remains
        // safely closable; post-initiation evidence failure is reported too.
        this.custodyFailed = true;
        this.outcomeFailureAfterInitiation ||= result.initiated === 1;
        return (published = {
          ...result,
          code: "INCONCLUSIVE",
          attempted: 1,
          outcomePersistence: "UNKNOWN",
          status: result.initiated ? "INITIATED_INCONCLUSIVE" : "ATTEMPTED_NO_WIRE"
        });
      }
      return (published = {
        ...result,
        attempted: 1,
        outcomePersistence: "COMMITTED",
        status: result.responseObserved
          ? "RESPONSE_OBSERVED"
          : result.initiated
            ? "INITIATED_INCONCLUSIVE"
            : "ATTEMPTED_NO_WIRE"
      });
    } catch {
      return (published = {
        ...empty("DENIED_OPERATOR_BINDING"),
        attempted: pending?.possiblyAttempted ? 1 : 0,
        status: pending?.possiblyAttempted ? "ATTEMPTED_NO_WIRE" : "DENIED"
      });
    } finally {
      this.sessions.releaseTrustedDiscoverySession(authority);
      if (pending) this.remove(pending);
      await Promise.all([...this.disposals]);
      if (published) {
        published.cleanup = this.disposalFailed ? "FAILED" : pending ? "CONFIRMED" : "NOT_REQUIRED";
        if (this.disposalFailed) {
          published.code = "INCONCLUSIVE";
          published.status = published.initiated
            ? "INITIATED_INCONCLUSIVE"
            : published.attempted
              ? "ATTEMPTED_NO_WIRE"
              : "DENIED";
        }
      }
    }
  }
  public async preconsent(
    input: z.infer<typeof trustedDiscoveryPreconsentSchema>,
    authority: object,
    organizationId: string
  ): Promise<ReturnType<typeof trustedDiscoveryStageAFacts>> {
    this.invalidateExpired();
    const actor = this.actor(authority, organizationId),
      session = this.sessions.revalidateTrustedDiscoverySession(authority);
    const selected = this.pending.get(input.reviewId);
    const pending =
      selected &&
      selected.actor.organizationId === actor.organizationId &&
      selected.actor.userId === actor.userId &&
      selected.sessionId === session.sessionId
        ? selected
        : undefined;
    try {
      if (!pending || this.closed) throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
      withTrustedDiscoveryDatabaseDeadline(this.database, () =>
        this.database.db
          .transaction(() => {
            this.verify(pending, authority, organizationId);
            const { confirmation: _confirmation, ...exact } = input;
            if (
              Object.keys(pending.publicReview).some(
                (key) => exact[key as keyof typeof exact] !== pending.publicReview[key as keyof PublicReview]
              )
            )
              throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
            this.store.preconsent(pending.id, pending.actor, pending.sessionId);
            this.verify(pending, authority, organizationId);
          })
          .immediate()
      );
      // Metadata records intention only. Original native review/context is invalidated here;
      // future Stage B must re-review and obtain its own fresh final-transport authority.
      this.remove(pending, false);
      return trustedDiscoveryStageAFacts("PRECONSENT_RECORDED");
    } catch (error) {
      if (pending) this.remove(pending);
      throw error;
    } finally {
      this.sessions.releaseTrustedDiscoverySession(authority);
    }
  }
  /** Polling revalidates native authority and immutable source; no traffic is performed.
   * Busy persistence never retains in-memory authority or becomes a successful grant. */
  private invalidateExpired(): void {
    // Fresh checks for the selected review run at every transition. Other sources are
    // swept by the lifecycle timer, avoiding quadratic report IO during new reviews.
    for (const value of this.pending.values())
      if (Date.now() >= Date.parse(value.publicReview.expiresAt)) this.remove(value);
  }
  public invalidateStale(): void {
    if (this.closed) return;
    for (const value of this.pending.values())
      try {
        this.verify(value, value.authority, value.actor.organizationId);
      } catch {
        this.remove(value);
      }
    for (const [id, org] of this.invalidations)
      try {
        this.store.invalidate(id, org);
        this.invalidations.delete(id);
      } catch {
        /* retry invalidation metadata only, never an attempted request */
      }
  }
  public invalidateAllPending(): void {
    for (const value of this.pending.values()) this.remove(value);
  }
  public async shutdown(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.timer);
    for (const value of this.pending.values()) this.remove(value);
    let timeout: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        (async () => {
          await Promise.all([...this.inFlight]);
          await Promise.all([...this.disposals]);
        })(),
        new Promise<never>((_done, reject) => {
          timeout = setTimeout(() => reject(Error("TRUSTED_DISCOVERY_SHUTDOWN_TIMEOUT")), 6000);
        })
      ]);
    } finally {
      if (timeout) clearTimeout(timeout);
      this.witness?.close();
      this.store.dispose();
    }
    if (this.disposalFailed) throw new Error("TRUSTED_DISCOVERY_DISPOSAL_FAILED");
    if (this.outcomeFailureAfterInitiation) throw new Error("TRUSTED_DISCOVERY_OUTCOME_COMMIT_FAILED");
  }
  private actor(authority: object, organizationId: string): TrustedDiscoveryActor {
    if (this.closed) throw new TrustedDiscoveryStageAError("DENIED_AUTHORITY", 403);
    const native = this.sessions.revalidateTrustedDiscoverySession(authority);
    if (this.organizations.require(organizationId, native.userId, "resources.use", false) !== "OWNER")
      throw new TrustedDiscoveryStageAError("DENIED_AUTHORITY", 403);
    return { organizationId, userId: native.userId };
  }
  private verify(pending: PendingReview, authority: object, organizationId: string): void {
    if (
      this.closed ||
      this.disposalFailed ||
      this.custodyFailed ||
      pending.controller.signal.aborted ||
      Date.now() >= Date.parse(pending.publicReview.expiresAt)
    )
      throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
    const actor = this.actor(authority, organizationId),
      original = this.actor(pending.authority, pending.actor.organizationId),
      session = this.sessions.revalidateTrustedDiscoverySession(authority);
    if (
      actor.organizationId !== pending.actor.organizationId ||
      actor.userId !== original.userId ||
      session.sessionId !== pending.sessionId
    )
      throw new TrustedDiscoveryStageAError("DENIED_AUTHORITY", 403);
    this.source.assertCurrent(pending.snapshot, actor);
    if (this.producerGeneration(pending.snapshot.scanId) !== pending.producerGeneration)
      throw new TrustedDiscoveryStageAError("DENIED_SOURCE");
    if (this.witness) {
      if (pending.reservation) {
        if (!pending.executing || !pending.operation || !pending.consentReceipt)
          throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
        this.witness.assertOwn(this.database, this.store, pending.reservation);
      } else this.witness.assertConsistent(this.database, this.store);
    }
    if (!pending.reservation && this.store.hasAttempt(actor, pending.snapshot.targetId, pending.route))
      throw new TrustedDiscoveryStageAError("DENIED_DUPLICATE");
    if (Date.now() >= Date.parse(pending.publicReview.expiresAt))
      throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
  }
  private producerGeneration(scanId: string): string {
    const lease = this.database.db.prepare("SELECT * FROM scan_job_leases WHERE job_id=?").get(scanId) as
      { worker_id: string; released_at: string | null } | undefined;
    if (lease && !lease.released_at) throw new TrustedDiscoveryStageAError("DENIED_SOURCE");
    const worker = lease
      ? this.database.db.prepare("SELECT * FROM scan_workers WHERE id=?").get(lease.worker_id)
      : undefined;
    return this.store.hash("producer-generation", [JSON.stringify({ lease: lease ?? null, worker: worker ?? null })]);
  }
  private remove(pending: PendingReview, invalidate = true): void {
    if (pending.removed) return;
    pending.removed = true;
    if (pending.publicReview) this.pending.delete(pending.publicReview.reviewId);
    pending.controller.abort();
    this.sessions.releaseTrustedDiscoverySession(pending.authority);
    if (invalidate) {
      try {
        this.store.invalidate(pending.id, pending.actor.organizationId);
      } catch {
        if (this.invalidations.size < 64) this.invalidations.set(pending.id, pending.actor.organizationId);
      }
    }
    const disposal = pending.context
      .dispose()
      .then(() => pending.privateRoot?.dispose())
      .catch(() => {
        this.disposalFailed = true;
      });
    this.disposals.add(disposal);
    void disposal.finally(() => this.disposals.delete(disposal));
  }
  private createContext(
    snapshot: TrustedDiscoverySnapshot,
    controller: AbortController,
    root?: TrustedDiscoveryPrivateRoot
  ): ScanContext {
    if (!snapshot.scope.allowedMethods.includes("GET")) throw new TrustedDiscoveryStageAError("DENIED_SCOPE");
    const scope = {
      ...snapshot.scope,
      allowedDomains: [new URL(snapshot.origin).hostname],
      allowedMethods: ["GET" as const],
      rateLimitPerSecond: 1,
      concurrency: 1,
      maxDepth: 0,
      sameOriginOnly: true,
      includeSubdomains: false,
      userAgent: "RouteCairn/0.1"
    };
    const config = {
      ...defaultConfig,
      requestTimeoutMs: 4000,
      bodyPreviewBytes: 1024,
      transport: { ...defaultConfig.transport, http2Enabled: false, poolingEnabled: false }
    };
    const resolved = new ScanPlanner(createDefaultPluginRegistry()).resolve({
      requestedProfile: "quick",
      scope,
      config,
      targetAuthorization: {
        schemaVersion: 1,
        mode: "INTERNAL_STAGING",
        targetOrigin: snapshot.origin,
        proof: {
          reference: "Registered owned loopback authorization; Stage A preview only",
          sha256: snapshot.targetGeneration
        }
      },
      overrides: {
        includeModules: ["api-mapper"],
        maxRequests: 3,
        cleanupReservedRequests: 1,
        evidenceLevel: "minimal"
      }
    });
    const plan = Object.freeze({
      ...resolved,
      limits: Object.freeze({
        ...resolved.limits,
        maxResponseBytes: 4096,
        maxScanDurationMs: 60_000,
        retry: Object.freeze({ ...resolved.limits.retry, maxAttempts: 1 })
      })
    });
    return new ScanContext({
      target: snapshot.origin,
      scope,
      config,
      plan,
      outputDir: root ? join(root.path, "output") : this.paths.reportsDir,
      ...(root ? { mutationJournalDir: join(root.path, "mutations") } : {}),
      abortSignal: controller.signal
    });
  }
}
