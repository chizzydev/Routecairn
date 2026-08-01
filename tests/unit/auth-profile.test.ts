import { describe, expect, it } from "vitest";
import { authHeadersForProfile, redactedCurlCommand, redactAuthMaterial, summarizeAuthProfile } from "../../src/core/auth/AuthProfile.js";

describe("auth profiles", () => {
  it("builds headers from cookies and redacts secrets", () => {
    const profile = {
      label: "account-a",
      headers: { Authorization: "Bearer secret-token" },
      cookies: [{ name: "session", value: "abc123session" }],
      notes: []
    };

    expect(authHeadersForProfile(profile)).toEqual({
      Authorization: "Bearer secret-token",
      Cookie: "session=abc123session"
    });
    expect(summarizeAuthProfile(profile)).toMatchObject({
      enabled: true,
      headerNames: ["Authorization"],
      cookieNames: ["session"],
      redactionApplied: true
    });
    expect(redactedCurlCommand("https://example.test/private", profile)).toContain("Authorization: <redacted>");
    expect(redactedCurlCommand("https://example.test/private", profile)).toContain("Cookie: <redacted>");
    expect(redactedCurlCommand("https://example.test/private", profile)).not.toContain("secret-token");
    expect(redactAuthMaterial("Bearer secret-token session=abc123session", profile)).toBe("<redacted> session=<redacted>");
  });
});
