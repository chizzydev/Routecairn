import { createHash } from "node:crypto";
import { z } from "zod";

const originSchema = z.string().url().refine((value) => { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) && url.origin === value; }, "An exact HTTP(S) origin is required.");
const pathSchema = z.string().min(1).max(1000).refine((value) => value.startsWith("/") && !/[?#%\\]/.test(value) && !value.split("/").some((part) => part === "." || part === ".."), "Use a canonical path, without query, fragment or encoding.");
const assetSchema = z.object({ origin: originSchema, pathPrefix: pathSchema }).strict();
const ruleSchema = z.object({ origin: originSchema, path: pathSchema, method: z.enum(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]), effect: z.enum(["READ", "AUTHENTICATION", "MUTATION", "DESTRUCTIVE"]), bodySha256: z.string().regex(/^[a-f0-9]{64}$/).optional() }).strict();

export const targetAuthorizationSchema = z.object({
  schemaVersion: z.literal(1),
  mode: z.enum(["OWNED_PRODUCTION", "INTERNAL_STAGING", "PRE_HANDOVER_ASSAULT", "BUG_BOUNTY_AUTHORIZED"]),
  targetOrigin: originSchema,
  proof: z.object({ reference: z.string().min(3).max(240), sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict(),
  bugBounty: z.object({
    program: z.string().min(3).max(160), platform: z.string().min(2).max(120),
    scopeDocumentSha256: z.string().regex(/^[a-f0-9]{64}$/),
    inScope: z.array(assetSchema).min(1).max(100), outOfScope: z.array(assetSchema).max(100),
    rules: z.array(z.string().min(1).max(500)).min(1).max(100), prohibitedActions: z.array(z.string().min(1).max(240)).min(1).max(100),
    startsAt: z.string().datetime(), expiresAt: z.string().datetime(),
    maxRequests: z.number().int().min(1).max(10000), rateLimitPerSecond: z.number().int().min(1).max(50),
    authenticationPermitted: z.boolean().default(false), mutationPermitted: z.boolean().default(false),
    destructivePermitted: z.boolean().default(false), racePermitted: z.boolean().default(false),
    disposableAccountsSupplied: z.boolean().default(false),
    requests: z.array(ruleSchema).max(200).default([]), reportMode: z.literal("BUG_BOUNTY_SAFE")
  }).strict().optional()
}).strict().superRefine((value, ctx) => {
  const fail = (message: string) => ctx.addIssue({ code: z.ZodIssueCode.custom, message });
  if ((value.mode === "BUG_BOUNTY_AUTHORIZED") !== Boolean(value.bugBounty)) fail("Only bug-bounty mode requires program rules.");
  const program = value.bugBounty;
  if (!program) return;
  if (Date.parse(program.startsAt) >= Date.parse(program.expiresAt)) fail("Invalid testing window.");
  if ((program.destructivePermitted || program.racePermitted) && !program.mutationPermitted) fail("Destructive/race permission requires mutation permission.");
  if (program.mutationPermitted && !program.disposableAccountsSupplied) fail("Mutations require supplied disposable accounts.");
  if (new Set(program.requests.map((rule) => `${rule.origin}${rule.path}:${rule.method}`)).size !== program.requests.length) fail("Duplicate request permissions.");
  for (const rule of program.requests) {
    if (!program.inScope.some((asset) => matchesAsset(new URL(`${rule.origin}${rule.path}`), asset)) || program.outOfScope.some((asset) => matchesAsset(new URL(`${rule.origin}${rule.path}`), asset))) fail("Request permission is outside program scope.");
    if (rule.effect === "READ" && !["GET", "HEAD", "OPTIONS"].includes(rule.method) && !rule.bodySha256) fail("Read-only POST/query permission must bind exact body bytes by SHA-256.");
    if (rule.method === "DELETE" && rule.effect !== "DESTRUCTIVE") fail("DELETE requires destructive permission.");
  }
});

export type TargetAuthorization = z.infer<typeof targetAuthorizationSchema>;

/** A single instance belongs to a scan and is shared by every HTTP/browser broker. */
export class TargetAuthorizationGuard {
  private transmitted = 0;
  private recent: number[] = [];
  public readonly plan: TargetAuthorization;
  public constructor(input: TargetAuthorization, private readonly now: () => number = Date.now) {
    this.plan = targetAuthorizationSchema.parse(input);
  }

  public check(url: string, method: string, body?: string | Buffer): string | undefined {
    const program = this.plan.bugBounty;
    if (!program) return;
    let parsed: URL;
    try { parsed = new URL(url); } catch { return "authorization-invalid-url"; }
    if (parsed.username || parsed.password || !["http:", "https:"].includes(parsed.protocol)) return "authorization-invalid-url";
    // Encoded separators/traversal are ambiguous across proxies and application routers.
    if (/[%\\;]/.test(url.split(/[?#]/, 1)[0]!.replace(/^https?:\/\//, "")) || parsed.pathname.includes("//")) return "authorization-ambiguous-path";
    const now = this.now();
    if (now < Date.parse(program.startsAt) || now >= Date.parse(program.expiresAt)) return "authorization-window-closed";
    if (program.outOfScope.some((asset) => matchesAsset(parsed, asset)) || !program.inScope.some((asset) => matchesAsset(parsed, asset))) return "authorization-asset-out-of-scope";
    const rule = program.requests.find((item) => item.origin === parsed.origin && item.path === parsed.pathname && item.method === method.toUpperCase());
    const effect = rule?.effect ?? (["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase()) ? "READ" : "UNAPPROVED");
    if (effect === "UNAPPROVED") return "authorization-request-not-approved";
    if (effect === "AUTHENTICATION" && !program.authenticationPermitted) return "authorization-authentication-prohibited";
    if ((effect === "MUTATION" || effect === "DESTRUCTIVE") && !program.mutationPermitted) return "authorization-mutation-prohibited";
    if (effect === "DESTRUCTIVE" && !program.destructivePermitted) return "authorization-destructive-prohibited";
    if (rule?.bodySha256 && body !== undefined && digest(body) !== rule.bodySha256) return "authorization-body-mismatch";
  }

  public reserve(url: string, method: string, body?: string | Buffer): string | undefined {
    const denied = this.check(url, method, body);
    if (denied) return denied;
    const program = this.plan.bugBounty;
    if (!program) return;
    const rule = program.requests.find((item) => `${item.origin}${item.path}` === new URL(url).origin + new URL(url).pathname && item.method === method.toUpperCase());
    if (rule?.bodySha256 && digest(body ?? "") !== rule.bodySha256) return "authorization-body-mismatch";
    if (this.transmitted >= program.maxRequests) return "authorization-budget-exhausted";
    const now = this.now();
    this.recent = this.recent.filter((time) => now - time < 1000);
    if (this.recent.length >= program.rateLimitPerSecond) return "authorization-rate-limit";
    this.recent.push(now); this.transmitted += 1;
  }

  public requireRemainingBudget(requests: number): void {
    const program = this.plan.bugBounty;
    if (program && this.transmitted + requests > program.maxRequests) throw new Error("TARGET_AUTHORIZATION_INSUFFICIENT_EXECUTION_AND_CLEANUP_BUDGET");
  }

  /** HTTP queues wait; browser interception remains fail-closed if its window is full. */
  public async waitForRate(signal?: AbortSignal, slots = 1): Promise<void> {
    const program = this.plan.bugBounty;
    if (!program) return;
    if (slots > program.rateLimitPerSecond) throw new Error("TARGET_AUTHORIZATION_RACE_EXCEEDS_RATE_LIMIT");
    while (true) {
      signal?.throwIfAborted();
      const now = this.now();
      this.recent = this.recent.filter((time) => now - time < 1000);
      if (this.recent.length + slots <= program.rateLimitPerSecond) return;
      const delay = Math.max(1, 1000 - (now - this.recent[0]!));
      await new Promise<void>((resolve) => setTimeout(resolve, Math.min(1000, delay)));
    }
  }

  public snapshot() { return { mode: this.plan.mode, proofSha256: this.plan.proof.sha256, transmittedRequests: this.transmitted, ...(this.plan.bugBounty ? { program: this.plan.bugBounty.program, reportMode: this.plan.bugBounty.reportMode, maxRequests: this.plan.bugBounty.maxRequests } : {}) }; }
}

function matchesAsset(url: URL, asset: { origin: string; pathPrefix: string }): boolean {
  const prefix = asset.pathPrefix.replace(/\/$/, "");
  return url.origin === asset.origin && (!prefix || url.pathname === prefix || url.pathname.startsWith(`${prefix}/`));
}
function digest(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }
