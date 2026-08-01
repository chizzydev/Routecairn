import { describe, expect, it } from "vitest";
import type { HttpResponse } from "../../src/core/http/HttpTypes.js";
import { TechnologyClassifier } from "../../src/modules/techFingerprint/TechnologyClassifier.js";

describe("TechnologyClassifier", () => {
  it("detects common frameworks and platforms from headers and body", () => {
    const classifier = new TechnologyClassifier();
    const technologies = classifier.classify([
      response({
        headers: {
          server: "Vercel",
          "x-powered-by": "Next.js",
          "set-cookie": "laravel_session=abc"
        },
        bodyPreview: '<html><script src="/_next/static/chunks/app.js"></script><a href="https://abc.supabase.co"></a></html>'
      })
    ]);

    expect(technologies.map((technology) => technology.name)).toEqual(expect.arrayContaining(["Next.js", "Laravel", "Vercel", "Supabase"]));
  });
});

function response(overrides: Partial<HttpResponse>): HttpResponse {
  return {
    requestedUrl: "https://example.com/",
    finalUrl: "https://example.com/",
    method: "GET",
    headers: {},
    responseTimeMs: 1,
    redirectChain: [],
    ...overrides
  };
}
