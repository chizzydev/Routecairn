import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { authHeadersForProfile, loadAuthProfile, redactedCurlCommand, redactAuthMaterial, summarizeAuthProfile } from "../../src/core/auth/AuthProfile.js";

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

  it("validates explicit identity verification configuration", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-auth-profile-"));
    await expect(
      loadAuthProfile(
        await writeJson(tempDir, "valid.json", {
          label: "account-a",
          principalId: "principal-a",
          headers: { Cookie: "session=a" },
          identityVerification: {
            mode: "required",
            endpoint: "/api/me",
            method: "GET",
            principalIdField: "user.id",
            tenantIdField: "organization.id",
            roleField: "roles[0]",
            anonymousMarkers: [{ field: "authenticated", value: false }]
          }
        })
      )
    ).resolves.toMatchObject({
      principalId: "principal-a",
      identityVerification: { mode: "required", endpoint: "/api/me", principalIdField: "user.id" }
    });

    await expect(
      loadAuthProfile(
        await writeJson(tempDir, "unsafe-method.json", {
          label: "bad",
          headers: {},
          identityVerification: { mode: "required", endpoint: "/api/me", method: "POST", principalIdField: "user.id" }
        })
      )
    ).rejects.toThrow();

    await expect(
      loadAuthProfile(await writeJson(tempDir, "missing-endpoint.json", { label: "bad", headers: {}, identityVerification: { mode: "required", principalIdField: "user.id" } }))
    ).rejects.toThrow(/endpoint/);

    await expect(
      loadAuthProfile(
        await writeJson(tempDir, "invalid-path.json", {
          label: "bad",
          headers: {},
          identityVerification: { mode: "required", endpoint: "/api/me", principalIdField: "user.*" }
        })
      )
    ).rejects.toThrow(/unsupported path/);

    await expect(
      loadAuthProfile(
        await writeJson(tempDir, "prototype-path.json", {
          label: "bad",
          headers: {},
          identityVerification: { mode: "required", endpoint: "/api/me", principalIdField: "__proto__.id" }
        })
      )
    ).rejects.toThrow(/forbidden path/);

    await expect(
      loadAuthProfile(
        await writeJson(tempDir, "deep-path.json", {
          label: "bad",
          headers: {},
          identityVerification: { mode: "required", endpoint: "/api/me", principalIdField: "a.b.c.d.e.f.g.h.i.j" }
        })
      )
    ).rejects.toThrow(/unsupported path/);

    await expect(
      loadAuthProfile(
        await writeJson(tempDir, "unknown-field.json", {
          label: "bad",
          headers: {},
          identityVerification: { mode: "required", endpoint: "/api/me", principalIdField: "user.id", discover: true }
        })
      )
    ).rejects.toThrow();
  });

  it("validates browser login secret references and redacts their values", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-browser-profile-"));
    const profile = await loadAuthProfile(await writeJson(tempDir, "browser.json", {
      label: "browser-account",
      headers: {},
      browserBootstrap: {
        schemaVersion: 1,
        loginSecrets: { password: "browser-only-secret" },
        login: {
          startUrl: "https://app.example.test/login",
          allowedWritePaths: ["/session"],
          successUrlPrefix: "https://app.example.test/app",
          steps: [{ action: "fill", selector: "#password", valueRef: "password" }, { action: "click", selector: "button[type=submit]" }]
        },
        journeys: [],
        proofCases: []
      }
    }));
    expect(profile.browserBootstrap?.login?.allowedWritePaths).toEqual(["/session"]);
    expect(redactAuthMaterial("value=browser-only-secret", profile)).toBe("value=<redacted>");

    await expect(loadAuthProfile(await writeJson(tempDir, "unused.json", {
      label: "bad-browser-account",
      headers: {},
      browserBootstrap: { schemaVersion: 1, loginSecrets: { unused: "secret" }, journeys: [], proofCases: [] }
    }))).rejects.toThrow(/require a login workflow|Unused browser login secret/);
  });
});

async function writeJson(tempDir: string, name: string, value: unknown): Promise<string> {
  const path = join(tempDir, name);
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  return path;
}
