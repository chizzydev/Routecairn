import { it, expect } from "vitest";
import { parseApplicationSchema } from "../../src/dashboard/execution/ApplicationSchemaParser.js";
it("never resolves an inherited component property as a local schema reference", () => {
  const document = JSON.stringify({
    openapi: "3.1.0",
    components: { schemas: {} },
    paths: {
      "/record": {
        get: {
          responses: {
            "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/constructor" } } } }
          }
        }
      }
    }
  });
  expect(() => parseApplicationSchema(document)).toThrow("WORKBENCH_SCHEMA_UNRESOLVED_REF");
});
