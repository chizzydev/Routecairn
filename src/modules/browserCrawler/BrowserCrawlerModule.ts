import { actorRegistryDigest } from "../../core/auth/ActorRegistry.js";
import { assessWorkflow } from "../../core/auth/AssessmentCapabilities.js";
import type { HttpMethod } from "../../core/http/HttpTypes.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { browserPolicyFromSettings } from "./BrowserPolicy.js";
import { PlaywrightCrawler } from "./PlaywrightCrawler.js";

export class BrowserCrawlerModule implements RouteCairnPlugin {
  public readonly name = "browser-crawler";
  public readonly description =
    "Renders the target with Playwright, supports isolated authenticated bootstrap, and captures redacted traffic without submitting application forms.";
  public readonly phase = "intelligence";
  public constructor(private readonly crawler: Pick<PlaywrightCrawler, "crawl"> = new PlaywrightCrawler()) {}

  public async run(context: ScanContext): Promise<ModuleResult> {
    if (context.options.plan.authentication.required && !context.options.authProfile) {
      return {
        pluginName: this.name,
        notes: [
          "Browser crawl skipped: an authenticated plan had no primary credential profile. RouteCairn refused to browse anonymously."
        ]
      };
    }

    const targetUrl = normalizeUrl(context.options.target);
    const method: HttpMethod = "GET";
    const decision = context.scopeMatcher.decide(targetUrl, method);
    context.state.recordScopeDecision(decision);

    if (!decision.allowed || !decision.normalizedUrl) {
      return {
        pluginName: this.name,
        notes: [`Browser crawl skipped: ${decision.reason}.`]
      };
    }

    try {
      let browserAuthProfile = context.options.authProfile;
      const registry = context.options.plan.actorRegistry;
      let registryWorkflow: import("../../reports/ReportTypes.js").BrowserCrawlReport["assessmentWorkflow"];
      if (registry) {
        const w = registry.workflows.find((w) => w.family === "BROWSER_OBSERVATION");
        if (w) {
          const d = assessWorkflow(
            registry,
            w.id,
            context.state.getIdentityVerification()?.actors,
            Date.now(),
            context.identityExecutionId
          );
          if (d.status !== "ELIGIBLE" || w.actorIds.length !== 1)
            return { pluginName: this.name, notes: ["BLOCKED: " + d.reason] };
          browserAuthProfile = context.actorProfile(w.actorIds[0]!);
          registryWorkflow = {
            registryId: registry.registryId,
            registryFingerprint: actorRegistryDigest(registry),
            workflowId: w.id,
            actorId: w.actorIds[0]!
          };
        } else if (registry.actors.some((a) => a.authentication.mechanism !== "ANONYMOUS"))
          return {
            pluginName: this.name,
            notes: ["NOT_ASSESSED: review a single-actor browser workflow; no anonymous downgrade."]
          };
      }
      const settings = context.moduleSettings("browser-crawler");
      const policy = browserPolicyFromSettings(settings, context.options.plan.limits, context.options.plan.evidence);
      const crawlerOptions = {
        targetUrl: decision.normalizedUrl,
        ...(context.options.plan.targetAuthorization?.productionCampaign && process.platform === "win32"
          ? { browserChannel: "msedge" as const }
          : {}),
        outputDir: context.options.outputDir,
        userAgent: context.options.scope.userAgent,
        timeoutMs: context.options.plan.limits.requestTimeoutMs,
        sameOriginOnly: context.options.scope.sameOriginOnly,
        policy,
        requestBroker: context.httpClient,
        onNetworkBoundaryStatus: (
          diagnostics: import("./BrowserNetworkBoundary.js").BrowserNetworkBoundaryDiagnostics
        ) => {
          void context.eventSink.emit({
            type: "OBSERVATION_RECORDED",
            moduleId: this.name,
            message: `Browser network boundary ${diagnostics.state.toLowerCase()}.`,
            metadata: { kind: "BROWSER_NETWORK_BOUNDARY", ...diagnostics }
          });
        },
        ...(browserAuthProfile ? { authProfile: browserAuthProfile } : {}),
        ...(context.options.abortSignal ? { abortSignal: context.options.abortSignal } : {})
      };
      let browserCrawl;
      try {
        browserCrawl = await this.crawler.crawl({ ...crawlerOptions, browserRestartCount: 0 });
      } catch (firstError) {
        if (context.options.abortSignal?.aborted) throw firstError;
        await context.eventSink.emit({
          type: "OBSERVATION_RECORDED",
          moduleId: this.name,
          message: "Browser process failed; restarting one isolated Chromium context.",
          metadata: { restartAttempt: 1 }
        });
        browserCrawl = await this.crawler.crawl({ ...crawlerOptions, browserRestartCount: 1 });
        browserCrawl.notes.push(
          "Chromium/browser context was restarted once and authenticated bootstrap was replayed from the in-memory profile."
        );
      }

      return {
        pluginName: this.name,
        browserCrawl: { ...browserCrawl, ...(registryWorkflow ? { assessmentWorkflow: registryWorkflow } : {}) },
        notes: browserCrawl.notes
      };
    } catch (error) {
      if (context.options.plan.authentication.required) throw error;
      const message = error instanceof Error ? error.message : "Unknown browser crawl error";
      return {
        pluginName: this.name,
        notes: [`Browser crawl failed: ${message}`]
      };
    }
  }
}
