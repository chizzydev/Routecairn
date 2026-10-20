import { it, expect } from "vitest";
import { observeLinks } from "../../src/modules/apiGraphql/ObservedLinks.js";
it("does not misattribute links whose HTML base changes their effective origin", () => {
  const body =
    '<html><head><base href="https://outside.invalid/"></head><body><a href="/hub/protected">link</a></body></html>';
  const result = observeLinks(body, "http://127.0.0.1:9000/index", "text/html", true);
  expect(result.candidates).toEqual([]);
  expect(result.excluded.HTML_BASE_OVERRIDE).toBe(1);
});

for (const raw of ["/hub/item?", "/hub/item#"])
  it("refuses empty URL delimiter provenance: " + raw, () => {
    expect(
      observeLinks(JSON.stringify({ href: raw }), "http://127.0.0.1:9000/hub/start", "application/json", true)
        .candidates
    ).toEqual([]);
  });
