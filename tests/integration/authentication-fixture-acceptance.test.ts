import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runAuthenticationFixtureAcceptance } from "../../src/validation/AuthenticationFixtureAcceptance.js";

describe("authentication fixture acceptance laboratory", () => {
  it("executes every provider emulator plus complete OIDC and browser passkey lifecycles", async () => {
    const directory = await mkdtemp(join(tmpdir(), "routecairn-auth-fixtures-"));
    const summary = await runAuthenticationFixtureAcceptance(directory);
    expect(summary.status).toBe("PASSED");
    expect(summary.providers.map((item) => item.provider)).toEqual(["AUTH0", "COGNITO", "CLERK", "FIREBASE", "SUPABASE_AUTH"]);
    expect(summary.providers.every((item) => item.status === "PASSED" && item.operations.length >= 4 && item.requests >= 4)).toBe(true);
    expect(summary.oidc).toMatchObject({ status: "PASSED", discovery: true, callback: true, pkce: true, idToken: true, replay: true });
    expect(summary.passkey).toMatchObject({ status: "PASSED", enrollment: true, login: true, signatureVerified: true, cleanup: true });
    const artifact = await readFile(join(summary.outputDirectory, "authentication-fixture-acceptance.json"), "utf8");
    for (const secret of ["auth0-management-secret", "clerk-service-secret", "firebase-emulator-key", "supabase-anon-key", "supabase-service-key", "Fixture-password-42!"]) expect(artifact).not.toContain(secret);
    expect(JSON.parse(artifact)).toMatchObject({ status: "PASSED", evidenceSha256: summary.evidenceSha256 });
  }, 60_000);
});
