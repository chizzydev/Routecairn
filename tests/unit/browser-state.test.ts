import { describe, expect, it } from "vitest";
import { ScanState } from "../../src/core/engine/ScanState.js";

describe("browser crawl state", () => {
  it("records browser crawl evidence and queues rendered links", () => {
    const state = new ScanState();

    state.recordModuleResult({
      pluginName: "browser-crawler",
      browserCrawl: {
        startUrl: "https://example.com/",
        renderedLinks: [{ path: "/rendered", source: "browser:rendered-link" }],
        networkRequests: [{ url: "https://example.com/api", method: "GET", resourceType: "fetch" }],
        consoleErrors: [{ type: "error", text: "boom" }],
        screenshotPath: "reports/example/screenshots/homepage.png",
        formsDetected: 1,
        formsSubmitted: 0,
        notes: ["Forms were detected but not submitted."]
      }
    });

    expect(state.getBrowserCrawl()?.formsSubmitted).toBe(0);
    expect(state.getQueuedPathCandidates()).toEqual([{ path: "/rendered", source: "browser:rendered-link" }]);
  });
});
