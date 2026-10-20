import { it, expect } from "vitest";
import { parseApplicationSchema, concreteSchemaPath } from "../../src/dashboard/execution/ApplicationSchemaParser.js";
const doc = (paths: unknown) => JSON.stringify({ openapi: "3.1.0", paths });
const operation = {
  parameters: [{ in: "path", name: "number", required: true, schema: { type: "integer" } }],
  get: {
    responses: {
      "200": {
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                record: {
                  type: "object",
                  properties: {
                    number: { type: "integer" },
                    tenant: { type: "string" },
                    secretToken: { type: "string" },
                    privateValue: { type: "string", writeOnly: true }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  post: { responses: { "200": {} } }
};
it("parses real GET path arguments and safe nested markers while excluding mutations", () => {
  const r = parseApplicationSchema(doc({ "/v2/records/{number}": operation }));
  expect(r.candidates[0]).toMatchObject({
    template: "/v2/records/:number",
    slots: [{ name: "number", type: "integer" }],
    markers: [
      { path: "record.number", type: "number" },
      { path: "record.tenant", type: "string" }
    ],
    provenance: "SCHEMA_SUGGESTED_UNVERIFIED"
  });
  expect(r.excluded).toEqual([
    { path: "/v2/records/{number}", method: "POST", reason: "NON_GET_EXCLUDED_NO_AUTHORITY" }
  ]);
  expect(r.executionAuthorized).toBe(false);
  expect(concreteSchemaPath(r.candidates[0]!, { number: "42" })).toBe("/v2/records/42");
});
it.each([
  "https://external.invalid/schema",
  "file:///owner.json",
  "#/components/schemas/a~1b",
  "#/components/schemas/../bad"
])("rejects untrusted reference %s without resolution", (ref) =>
  expect(() =>
    parseApplicationSchema(
      JSON.stringify({ openapi: "3.0.3", paths: {}, components: { schemas: { Bad: { $ref: ref } } } })
    )
  ).toThrow("WORKBENCH_SCHEMA_EXTERNAL_OR_UNSAFE_REF")
);
it.each([
  "/v2/../owner",
  "//external.invalid",
  "/v2/%2e%2e/owner",
  "/v2/x?token=y",
  "/v2/{number}/",
  "/v2/./owner",
  "/v2/a\\b"
])("rejects malformed/normalized path %s", (path) =>
  expect(() => parseApplicationSchema(doc({ [path]: operation }))).toThrow("WORKBENCH_SCHEMA_UNSAFE_PATH")
);
it.each(["../owner", "%2fowner", "42?x=y", "-1", "1.1", "0042", "42/owner"])(
  "refuses unsafe or non-integer slot %s",
  (value) =>
    expect(() =>
      concreteSchemaPath(parseApplicationSchema(doc({ "/v2/{number}": operation })).candidates[0]!, { number: value })
    ).toThrow()
);
it("refuses poison, malformed, unsupported, oversized and deep structures", () => {
  expect(() => parseApplicationSchema('{"openapi":"3.1.0","paths":{},"__proto__":{}}')).toThrow("POISON");
  expect(() => parseApplicationSchema("openapi: 3.0.0")).toThrow("JSON_REQUIRED");
  expect(() => parseApplicationSchema('{"openapi":"2.0","paths":{}}')).toThrow("30_31_REQUIRED");
  expect(() => parseApplicationSchema(" ".repeat(262145))).toThrow("SIZE_LIMIT");
  expect(() =>
    parseApplicationSchema('{"openapi":"3.1.0","paths":{},"deep":' + "[".repeat(25) + "0" + "]".repeat(25) + "}")
  ).toThrow("STRUCTURE_LIMIT");
});
it("excludes required query arguments, overrides and body-based GET rather than inventing contracts", () => {
  const r = parseApplicationSchema(
    doc({
      "/query": {
        get: { parameters: [{ in: "query", name: "required", required: true, schema: { type: "string" } }] }
      },
      "/override": { get: { servers: [{ url: "http://external.invalid" }] } },
      "/body": { get: { requestBody: {} } }
    })
  );
  expect(r.candidates).toEqual([]);
  expect(r.excluded).toHaveLength(3);
});
it("enforces path count, safe missing refs and cycles", () => {
  expect(() =>
    parseApplicationSchema(doc(Object.fromEntries(Array.from({ length: 129 }, (_, i) => ["/r" + i, { get: {} }]))))
  ).toThrow("PATH_LIMIT");
  expect(() =>
    parseApplicationSchema(
      doc({
        "/x": {
          get: {
            responses: {
              "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/Missing" } } } }
            }
          }
        }
      })
    )
  ).toThrow("UNRESOLVED_REF");
  const d = {
    openapi: "3.1.0",
    paths: { "/x": { get: { parameters: [{ $ref: "#/components/parameters/A" }] } } },
    components: { parameters: { A: { $ref: "#/components/parameters/A" } } }
  };
  expect(() => parseApplicationSchema(JSON.stringify(d))).toThrow("CYCLIC_REF");
});
