import { withTrustedDiscoveryDatabaseDeadline } from "./TrustedDiscoveryDatabaseDeadline.js";
import { randomBytes, randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
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
  type TrustedDiscoverySnapshot,
} from "./TrustedDiscoverySource.js";
import { planAdaptiveDiscoveryCandidates } from "./AdaptiveDiscoveryCandidatePlanner.js";
import { TrustedDiscoveryReviewStore, TrustedDiscoveryStageAError } from "./TrustedDiscoveryReviewStore.js";

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
    expiresAt: z.string().datetime(),
  })
  .strict();
export const trustedDiscoveryPreconsentSchema = exactReviewSchema
  .extend({ confirmation: z.literal("I_CONFIRM_ONE_ANONYMOUS_NON_MUTATING_LOCAL_GET") })
  .strict();
type PublicReview = z.infer<typeof exactReviewSchema>;
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
}
export const trustedDiscoveryStageAFacts = (code: string) => ({
  code,
  status: "NOT_EXECUTED" as const,
  attempted: 0,
  initiated: 0,
  observed: 0,
  executionAuthority: "NONE" as const,
});

/** Lifecycle owned by a loopback, server-mode dashboard. Neither operation minting nor
 * transport is available from this service. DB metadata cannot revive its native tokens. */
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
  public constructor(
    private readonly database: DashboardDatabase,
    private readonly paths: DashboardPaths,
    private readonly sessions: ServerSessionManager,
  ) {
    this.source = new TrustedDiscoverySource(database, paths.reportsDir);
    this.store = new TrustedDiscoveryReviewStore(database, join(paths.dataDir, "keys", "trusted-discovery-review.key"));
    this.organizations = new OrganizationService(database);
    this.timer = setInterval(() => this.invalidateStale(), 1000);
    this.timer.unref();
  }
  public async review(
    input: z.infer<typeof trustedDiscoveryReviewSchema>,
    authority: object,
    organizationId: string,
  ): Promise<ReturnType<typeof trustedDiscoveryStageAFacts> & { review: PublicReview }> {
    this.invalidateExpired();
    if (this.closed || this.pending.size >= 64) throw new TrustedDiscoveryStageAError("DENIED_CAPACITY");
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
            const producerGeneration = this.producerGeneration(snapshot.scanId);
            const controller = new AbortController();
            const context = this.createContext(snapshot, controller);
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
            };
            const host: OwnedFixtureDiscoveryHost = {
              verifyActor: (receipt) => (receipt === authority ? this.actor(authority, organizationId) : undefined),
              // Stage A never issues an executable operation, including through native consent.
              verifyConsent: () => undefined,
            };
            pending.dispatcher = new TrustedDiscoveryDispatcher({
              database: this.database,
              reportRoot: this.paths.reportsDir,
              context,
              host,
            });
            const selected = pending.dispatcher.review(input, authority);
            if (!selected.review)
              throw new TrustedDiscoveryStageAError(
                selected.result.code === "DENIED_SCOPE" ? "DENIED_SCOPE" : "DENIED_SOURCE",
              );
            pending.nativeReview = selected.review;
            const candidate = planAdaptiveDiscoveryCandidates(snapshot.report).candidates.find(
              (v) => v.candidateId === input.candidateId,
            )!;
            pending.route = new URL(
              snapshot.report.apiMapper!.endpoints[candidate.sourceReferences[0]!.sourceIndex]!.endpoint,
              snapshot.origin,
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
              String(expiresAt),
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
              expiresAt: new Date(expiresAt).toISOString(),
            };
            this.verify(pending, authority, organizationId);
            this.store.save({
              id: pending.id,
              actor,
              sessionId: native.sessionId,
              snapshot: {
                ...snapshot,
                generation: this.store.hash("source-with-producer", [snapshot.generation, pending.producerGeneration]),
              },
              candidateId: input.candidateId,
              route: pending.route,
              createdAt,
              expiresAt,
              reviewDigest,
            });
            this.verify(pending, authority, organizationId);
          })
          .immediate(),
      );
      this.pending.set(pending!.publicReview.reviewId, pending!);
      return { ...trustedDiscoveryStageAFacts("REVIEWED"), review: { ...pending!.publicReview } };
    } catch (error) {
      if (pending) this.remove(pending);
      else this.sessions.releaseTrustedDiscoverySession(authority);
      throw error;
    }
  }
  public async preconsent(
    input: z.infer<typeof trustedDiscoveryPreconsentSchema>,
    authority: object,
    organizationId: string,
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
                (key) => exact[key as keyof typeof exact] !== pending.publicReview[key as keyof PublicReview],
              )
            )
              throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
            this.store.preconsent(pending.id, pending.actor, pending.sessionId);
            this.verify(pending, authority, organizationId);
          })
          .immediate(),
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
    await Promise.all([...this.disposals]);
    this.store.dispose();
    if (this.disposalFailed) throw new Error("TRUSTED_DISCOVERY_DISPOSAL_FAILED");
  }
  private actor(authority: object, organizationId: string): TrustedDiscoveryActor {
    if (this.closed) throw new TrustedDiscoveryStageAError("DENIED_AUTHORITY", 403);
    const native = this.sessions.revalidateTrustedDiscoverySession(authority);
    if (this.organizations.require(organizationId, native.userId, "resources.use", false) !== "OWNER")
      throw new TrustedDiscoveryStageAError("DENIED_AUTHORITY", 403);
    return { organizationId, userId: native.userId };
  }
  private verify(pending: PendingReview, authority: object, organizationId: string): void {
    if (this.closed || pending.controller.signal.aborted || Date.now() >= Date.parse(pending.publicReview.expiresAt))
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
    if (this.store.hasAttempt(actor, pending.snapshot.targetId, pending.route))
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
    const disposal = pending.context.dispose().catch(() => {
      this.disposalFailed = true;
    });
    this.disposals.add(disposal);
    void disposal.finally(() => this.disposals.delete(disposal));
  }
  private createContext(snapshot: TrustedDiscoverySnapshot, controller: AbortController): ScanContext {
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
      userAgent: "RouteCairn/0.1",
    };
    const config = {
      ...defaultConfig,
      requestTimeoutMs: 4000,
      bodyPreviewBytes: 1024,
      transport: { ...defaultConfig.transport, http2Enabled: false, poolingEnabled: false },
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
          sha256: snapshot.targetGeneration,
        },
      },
      overrides: {
        includeModules: ["api-mapper"],
        maxRequests: 3,
        cleanupReservedRequests: 1,
        evidenceLevel: "minimal",
      },
    });
    const plan = Object.freeze({
      ...resolved,
      limits: Object.freeze({
        ...resolved.limits,
        maxResponseBytes: 4096,
        maxScanDurationMs: 60_000,
        retry: Object.freeze({ ...resolved.limits.retry, maxAttempts: 1 }),
      }),
    });
    return new ScanContext({
      target: snapshot.origin,
      scope,
      config,
      plan,
      outputDir: this.paths.reportsDir,
      abortSignal: controller.signal,
    });
  }
}
