import { describe, expect, it } from "vitest";
import type { HttpResponse } from "../../src/core/http/HttpTypes.js";
import { cookieFindings } from "../../src/modules/cookieReview/CookieRules.js";
import { corsFinding } from "../../src/modules/corsReview/CorsRules.js";
import { headerFindings } from "../../src/modules/headerReview/HeaderRules.js";
import { methodFindings } from "../../src/modules/methodReview/MethodRules.js";

describe("security review modules", () => {
  it("uses realistic header severities", () => {
    const findings = headerFindings(
      response({
        finalUrl: "https://example.com/",
        headers: {
          server: "nginx/1.24.0",
          "x-powered-by": "Express"
        }
      })
    );

    expect(findings.some((finding) => finding.title.includes("Strict-Transport-Security") && finding.severity === "Medium")).toBe(true);
    expect(findings.some((finding) => finding.title.includes("X-Powered-By") && finding.severity === "Informational")).toBe(true);
  });

  it("scores sensitive cookie attribute issues higher than preference cookies", () => {
    const findings = cookieFindings(
      response({
        headers: {
          "set-cookie": ["session=abc; Path=/; SameSite=Lax", "theme=dark; Path=/"]
        }
      })
    );

    expect(findings.some((finding) => finding.evidence.source?.startsWith("session:") && finding.severity === "Medium")).toBe(true);
    expect(findings.some((finding) => finding.evidence.source?.startsWith("theme:") && finding.severity === "Informational")).toBe(true);
  });

  it("does not overstate wildcard CORS without credentials", () => {
    const finding = corsFinding(
      response({
        headers: {
          "access-control-allow-origin": "*"
        }
      }),
      "https://example-attacker.invalid"
    );

    expect(finding?.severity).toBe("Informational");
  });

  it("reports reflected credentialed CORS as high severity", () => {
    const finding = corsFinding(
      response({
        headers: {
          "access-control-allow-origin": "https://example-attacker.invalid",
          "access-control-allow-credentials": "true"
        }
      }),
      "https://example-attacker.invalid"
    );

    expect(finding?.severity).toBe("High");
  });

  it("reports dangerous advertised methods", () => {
    const findings = methodFindings(
      response({
        method: "OPTIONS",
        headers: {
          allow: "GET, POST, PUT, DELETE, OPTIONS"
        }
      })
    );

    expect(findings.some((finding) => finding.type === "HTTP Method Issue")).toBe(true);
  });
});

function response(overrides: Partial<HttpResponse>): HttpResponse {
  return {
    requestedUrl: "https://example.com/",
    finalUrl: "https://example.com/",
    method: "GET",
    statusCode: 200,
    headers: {},
    responseTimeMs: 1,
    redirectChain: [],
    ...overrides
  };
}
