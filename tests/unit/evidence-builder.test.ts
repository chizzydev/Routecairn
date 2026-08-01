import { describe, expect, it } from "vitest";
import { evidenceFromResponse, redactBodyPreview, redactHeaders } from "../../src/core/evidence/EvidenceBuilder.js";
import type { HttpResponse } from "../../src/core/http/HttpTypes.js";

describe("evidence builder", () => {
  it("stores reproducible response evidence while redacting sensitive data", () => {
    const evidence = evidenceFromResponse(response(), {
      source: "Missing Strict-Transport-Security header.",
      severity: "Medium",
      confidence: "High",
      tags: ["headers", "hsts"]
    });

    expect(evidence.statusCode).toBe(200);
    expect(evidence.contentLength).toBe(321);
    expect(evidence.contentType).toContain("text/html");
    expect(evidence.responseHeaders?.["set-cookie"]).toEqual(["<redacted>"]);
    expect(evidence.bodyPreview).toContain("api_key=<redacted>");
    expect(evidence.bodyPreview).not.toContain("super-secret-value");
    expect(evidence.curlCommand).toBe('curl -i -X GET "https://example.com/admin"');
    expect(evidence.severityReason).toContain("Medium severity with High confidence");
  });

  it("redacts sensitive headers and body previews directly", () => {
    expect(
      redactHeaders({
        authorization: "Bearer secret",
        server: "nginx",
        "set-cookie": ["session=secret; HttpOnly"]
      })
    ).toEqual({
      authorization: "<redacted>",
      server: "nginx",
      "set-cookie": ["<redacted>"]
    });

    expect(redactBodyPreview("DATABASE_URL=postgres://user:pass@example/db password=hunter2 visible=true")).toContain(
      "DATABASE_URL=<redacted>"
    );
  });
});

function response(): HttpResponse {
  return {
    requestedUrl: "https://example.com/admin",
    finalUrl: "https://example.com/admin",
    method: "GET",
    statusCode: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "set-cookie": ["session=super-secret-value; Path=/; HttpOnly"],
      server: "nginx"
    },
    contentType: "text/html; charset=utf-8",
    contentLength: 321,
    bodyPreview: "<html><title>Admin</title><script>const api_key=super-secret-value</script></html>",
    bodyHash: "abc123",
    responseTimeMs: 12,
    redirectChain: []
  };
}
