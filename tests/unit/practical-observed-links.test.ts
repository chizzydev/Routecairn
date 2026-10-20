import { it, expect } from "vitest";
import { observeLinks } from "../../src/modules/apiGraphql/ObservedLinks.js";
import { observedRoutePattern } from "../../src/dashboard/execution/ObservedRoutePatterns.js";
const origin = "http://127.0.0.1:1234/catalog";
it("passively extracts concrete JSON:API pagination and related links without guessing identifiers", () => {
  const r = observeLinks(
    JSON.stringify({
      data: [{ id: "987", relationships: { owner: { links: { related: "/users/41" } } } }],
      links: { self: "/catalog", next: "/catalog/page/2", evil: "/never" }
    }),
    origin,
    "application/vnd.api+json",
    true
  );
  expect(r.candidates.map((c) => c.path)).toEqual(["/catalog", "/catalog/page/2", "/users/41"]);
  expect(r.truncated).toBe(false);
});
it("extracts HAL and HTML head pagination with all original refusal rules", () => {
  const r = observeLinks(
    JSON.stringify({
      _links: {
        self: { href: "/items/1" },
        next: "/items/page/2",
        related: "https://outside.invalid/x",
        prev: "/items/../secret"
      }
    }),
    origin,
    "application/hal+json",
    true
  );
  expect(r.candidates.map((c) => c.path)).toEqual(["/items/1", "/items/page/2"]);
  expect(r.excluded.ORIGIN_MISMATCH).toBe(1);
  expect(
    observeLinks(
      '<head><link rel="next" href="/catalog/page/2"></head><a href="/delete">unsafe</a>',
      origin,
      "text/html",
      true
    ).candidates.map((c) => c.path)
  ).toEqual(["/catalog/page/2"]);
});
it("retains bounds, incomplete abstention and base ambiguity for all new link forms", () => {
  const body = JSON.stringify(Array.from({ length: 35 }, (_, i) => ({ links: { related: "/record/" + i } })));
  const r = observeLinks(body, origin, "application/json", true);
  expect(r.candidates).toHaveLength(32);
  expect(r.truncated).toBe(true);
  expect(observeLinks(body, origin, "application/json", false).candidates).toEqual([]);
  expect(observeLinks('<base href="/other"><link rel="next" href="/x">', origin, "text/html", true).truncated).toBe(
    true
  );
});
it("proposes path parameter shapes without inventing a request or an authorization rule", () => {
  expect(observedRoutePattern("/books/41/items/88")).toEqual({
    suggestedTemplate: "/books/{observed1}/items/{observed2}",
    parameterCount: 2,
    authority: "ADVISORY_ONLY_NO_ENUMERATION"
  });
});
