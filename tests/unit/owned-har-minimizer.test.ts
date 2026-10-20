import { it, expect } from "vitest";
import { minimizeOwnedHar } from "../../src/dashboard/execution/OwnedHarMinimizer.js";
const routes = [
  {
    id: "seed",
    kind: "OBJECT",
    method: "GET",
    url: "http://127.0.0.1:8099/record/7",
    pathTemplate: "/record/7",
    identityPath: "record.id",
    tenantPath: "record.tenant"
  }
];
const metadata = {
  version: 1,
  origin: "http://127.0.0.1:8099",
  provenance: "OWNER_LOCAL_APPLICATION",
  routes,
  actors: ["primary", "account_a", "account_b"].map((slot) => ({
    slot,
    principalFingerprint: "1".repeat(16),
    tenantFingerprint: "2".repeat(16),
    roleFingerprint: "3".repeat(16),
    sessionEvidenceSha256: "a".repeat(64)
  }))
};
it("minimizes actual HAR-shaped bytes to allowlisted metadata without headers, response contents, cookies or unselected requests", () => {
  const raw = Buffer.from(
    JSON.stringify({
      log: {
        entries: [
          {
            startedDateTime: new Date().toISOString(),
            request: {
              method: "GET",
              url: routes[0]!.url,
              headers: [{ name: "Authorization", value: "Bearer synthetic-har-secret" }],
              cookies: [{ value: "synthetic-cookie" }]
            },
            response: { content: { text: "synthetic-private-body" } }
          },
          {
            startedDateTime: new Date().toISOString(),
            request: { method: "POST", url: "https://external.example/login", postData: { text: "synthetic-password" } }
          }
        ]
      }
    })
  );
  const output = minimizeOwnedHar(raw, metadata);
  expect(output.kind).toBe("MINIMIZED_HAR");
  expect(JSON.stringify(output)).not.toMatch(/synthetic-|postData|headers|cookies|external/);
  expect(output.routes).toHaveLength(1);
});
it("refuses unobserved selected GETs and malformed/oversized exports", () => {
  expect(() => minimizeOwnedHar(Buffer.from('{"log":{"entries":[]}}'), metadata)).toThrow("GET_MISSING");
  expect(() => minimizeOwnedHar(Buffer.alloc(8388609), metadata)).toThrow("SIZE_BOUND");
  expect(() => minimizeOwnedHar(Buffer.from("{}"), metadata)).toThrow();
});
