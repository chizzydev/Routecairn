import { it, expect } from "vitest";
import {
  observePublicDocument,
  structuralUrl
} from "../../src/intelligence/inventory/ProductionApplicationDiscovery.js";
it("bounds public metadata, strips query values, identifies Next.js and never grants execution", () => {
  const r = observePublicDocument(
    '<link rel="canonical" href="https://www.example.test/"><script src="/_next/static/app.js"></script><form action="https://auth.example.test/login?secret=not-retained"></form>',
    "https://entry.example.test/",
    { link: '<https://api.example.test/openapi.json>; rel="service-desc"' },
    true
  );
  expect(r.framework).toBe("NEXTJS");
  expect(r.candidates.some((c) => c.origin === "https://api.example.test")).toBe(true);
  expect(JSON.stringify(r)).not.toContain("not-retained");
  expect(r.candidates.some((c) => c.source === "HTML_FORM")).toBe(true);
});
it("does not promote oversized or truncated source to complete discovery", () => {
  expect(observePublicDocument("x".repeat(1024 * 1024 + 1), "https://owned.example.test/", {}, true).complete).toBe(
    false
  );
  expect(observePublicDocument("<a href='/login'>login</a>", "https://owned.example.test/", {}, false).complete).toBe(
    false
  );
  const r = observePublicDocument(
    Array.from({ length: 150 }, (_, i) => `<a href='/route-${i}'>route</a>`).join(""),
    "https://owned.example.test/",
    {},
    true
  );
  expect(r.candidateBoundExceeded).toBe(true);
  expect(r.candidates.length).toBe(128);
  expect(r.complete).toBe(false);
});
it("refuses credential-bearing origins and minimizes object identities", () => {
  expect(structuralUrl("https://name:password@example.test/secret")).toBeUndefined();
  expect(structuralUrl("https://example.test/api/users/customer-name?token=never-retain")).toEqual({
    origin: "https://example.test",
    path: "/api/users/:id",
    hadQuery: true
  });
});
