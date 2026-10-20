import { it, expect, vi } from "vitest";
import type { ScanContext } from "../../src/core/engine/ScanContext.js";
const calls = vi.hoisted(() => ({ constructed: 0, run: 0 }));
vi.mock("../../src/modules/apiGraphql/ApiGraphqlModule.js", () => ({
  ApiGraphqlModule: class {
    name = "api-graphql-authorization";
    phase = "analysis" as const;
    description = "Owned import regression stub";
    constructor() {
      calls.constructed++;
    }
    async run() {
      calls.run++;
      return { pluginName: this.name };
    }
  }
}));
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
it("does not instantiate an unselected detector while enumerating planning metadata", async () => {
  const r = createDefaultPluginRegistry();
  expect(r.list().length).toBeGreaterThan(30);
  expect(r.get("api-graphql-authorization")?.metadata.phase).toBe("analysis");
  expect(calls.constructed).toBe(0);
  const context = { options: {} } as ScanContext;
  await r.get("api-graphql-authorization")!.plugin.run(context);
  expect(calls.constructed).toBe(1);
  expect(calls.run).toBe(1);
  await r.get("api-graphql-authorization")!.plugin.run(context);
  expect(calls.constructed).toBe(1);
  expect(calls.run).toBe(2);
});
