import { it, expect } from "vitest";
import { JsDiscoveryModule } from "../../src/modules/jsIntelligence/JsDiscoveryModule.js";
import type { ScanContext } from "../../src/core/engine/ScanContext.js";
it("mines an approved canonical redirect page's own assets without granting third-party scope", async () => {
  const sent: string[] = [];
  const context = {
    options: { target: "https://entry.example.test/" },
    scopeMatcher: {
      decide: (url: string) => ({
        allowed: new URL(url).origin === "https://canonical.example.test",
        normalizedUrl: url,
        reason: "explicit fixture scope"
      })
    },
    state: {
      getResponses: () => [
        {
          requestedUrl: "https://entry.example.test/",
          finalUrl: "https://canonical.example.test/",
          contentType: "text/html",
          bodyPreview:
            '<script src="/_next/static/app.js"></script><script src="https://analytics.example.test/beacon.js"></script>'
        }
      ],
      recordScopeDecision: () => {},
      recordResponse: () => {}
    },
    httpClient: {
      send: async ({ url }: { url: string }) => {
        sent.push(url);
        return {
          requestedUrl: url,
          finalUrl: url,
          statusCode: 200,
          bodyPreview: 'fetch("https://api.example.test/api/products")',
          headers: {},
          streamTruncated: false
        };
      }
    }
  } as unknown as ScanContext;
  const result = await new JsDiscoveryModule().run(context);
  expect(result.jsIntelligence?.scripts[0]?.downloaded).toBe(true);
  expect(sent).toEqual(["https://canonical.example.test/_next/static/app.js"]);
  expect(result.jsIntelligence?.scripts[1]?.downloaded).toBe(false);
});
