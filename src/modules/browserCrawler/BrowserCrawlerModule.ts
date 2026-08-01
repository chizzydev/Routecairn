import type { HttpMethod } from "../../core/http/HttpTypes.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { browserPolicyFromSettings } from "./BrowserPolicy.js";
import { PlaywrightCrawler } from "./PlaywrightCrawler.js";

export class BrowserCrawlerModule implements RouteCairnPlugin {
  public readonly name = "browser-crawler";
  public readonly description = "Renders the target with Playwright, captures screenshots, links, console errors, and network requests without submitting forms.";
  public readonly phase = "intelligence";
  private readonly crawler = new PlaywrightCrawler();

  public async run(context: ScanContext): Promise<ModuleResult> {
    if (context.options.plan.authentication.required) {
      return {
        pluginName: this.name,
        notes: [
          "Browser crawl skipped: authenticated browser bootstrap is not implemented, so RouteCairn will not browse anonymously during an authenticated scan."
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
      const settings = context.moduleSettings("browser-crawler");
      const policy = browserPolicyFromSettings(settings, context.options.plan.limits, context.options.plan.evidence);
      const browserCrawl = await this.crawler.crawl({
        targetUrl: decision.normalizedUrl,
        outputDir: context.options.outputDir,
        userAgent: context.options.scope.userAgent,
        timeoutMs: context.options.plan.limits.requestTimeoutMs,
        sameOriginOnly: context.options.scope.sameOriginOnly,
        policy,
        requestBroker: context.httpClient
      });

      return {
        pluginName: this.name,
        browserCrawl,
        notes: browserCrawl.notes
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown browser crawl error";
      return {
        pluginName: this.name,
        notes: [`Browser crawl failed: ${message}`]
      };
    }
  }
}
