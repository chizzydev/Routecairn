import { it, expect } from "vitest";
import { observeLinks } from "../../src/modules/apiGraphql/ObservedLinks.js";
const url = "http://127.0.0.1:9000/catalog/start";
it("extracts bounded JSON and HTML provenance without following advertisements", () => {
  const a = observeLinks(
    JSON.stringify({
      links: [
        { href: "/catalog/next" },
        { href: "/catalog/next" },
        { href: "https://outside.invalid/x" },
        { href: "/catalog/change", method: "POST" }
      ]
    }),
    url,
    "application/json",
    true
  );
  expect(a.candidates.map((c) => c.path)).toEqual(["/catalog/next"]);
  expect(a.excluded).toEqual({ DUPLICATE: 1, ORIGIN_MISMATCH: 1, NON_GET_ADVERTISEMENT: 1 });
  const b = observeLinks('<a href="/catalog/page/2">next</a>', url, "text/html", true);
  expect(b.candidates[0]?.path).toBe("/catalog/page/2");
  expect(b.responseFingerprint).toMatch(/^[a-f0-9]{64}$/);
});
for (const raw of [
  "../escape",
  "/catalog/../escape",
  "//127.0.0.1:9000/escape",
  "/x?credential=secret",
  "/x#fragment",
  "/x%2fsecret",
  "/logout",
  "/delete/x",
  "http://user:pass@127.0.0.1:9000/x",
  "javascript:alert(1)",
  "/x\\evil"
])
  it("refuses ambiguous or unsafe link " + raw, () => {
    expect(observeLinks(JSON.stringify({ href: raw }), url, "application/json", true).candidates).toEqual([]);
  });
it("reports incomplete capture and exhausted bounds rather than claiming complete discovery", () => {
  expect(observeLinks('{"href":"/catalog/x"}', url, "application/json", false).candidates).toEqual([]);
  const r = observeLinks(
    JSON.stringify(Array.from({ length: 35 }, (_, i) => ({ href: "/catalog/" + i }))),
    url,
    "application/json",
    true
  );
  expect(r.candidates).toHaveLength(32);
  expect(r.truncated).toBe(true);
  expect(observeLinks("x".repeat(8193), url, "text/html", true).candidates).toEqual([]);
});
