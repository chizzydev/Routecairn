import { it, expect, vi } from "vitest";
import { DeferredPlugin } from "../../src/core/plugins/DeferredPlugin.js";
import { moduleMetadata } from "../../src/core/planning/ModuleCatalog.js";
import type { ScanContext } from "../../src/core/engine/ScanContext.js";
const context = (signal?: AbortSignal) => ({ options: { abortSignal: signal } }) as ScanContext;
const plugin = () => ({
  name: "baseline",
  description: "Owned deferred test",
  phase: "baseline" as const,
  run: vi.fn(async () => ({ pluginName: "baseline" }))
});
it("does not load for a pre-cancelled context", async () => {
  const c = new AbortController();
  c.abort();
  const load = vi.fn(async () => plugin()),
    d = new DeferredPlugin(moduleMetadata("baseline"), load);
  await expect(d.run(context(c.signal))).rejects.toThrow();
  expect(load).not.toHaveBeenCalled();
});
it("isolates a cancellation during one shared load from a different live context", async () => {
  let ready!: (p: ReturnType<typeof plugin>) => void;
  const pending = new Promise<ReturnType<typeof plugin>>((r) => {
      ready = r;
    }),
    load = vi.fn(() => pending),
    d = new DeferredPlugin(moduleMetadata("baseline"), load),
    c = new AbortController(),
    p = plugin(),
    a = d.run(context(c.signal)),
    b = d.run(context());
  c.abort();
  ready(p);
  await expect(a).rejects.toThrow();
  await expect(b).resolves.toEqual({ pluginName: "baseline" });
  expect(load).toHaveBeenCalledTimes(1);
  expect(p.run).toHaveBeenCalledTimes(1);
});
for (const field of ["name", "phase"] as const)
  it("permanently refuses a mismatched built-in " + field, async () => {
    const p = plugin();
    const bad = { ...p, [field]: field === "name" ? "other" : "analysis" } as ReturnType<typeof plugin>,
      load = vi.fn(async () => bad),
      d = new DeferredPlugin(moduleMetadata("baseline"), load);
    await expect(d.run(context())).rejects.toThrow("IDENTITY_MISMATCH");
    await expect(d.run(context())).rejects.toThrow("IDENTITY_MISMATCH");
    expect(load).toHaveBeenCalledTimes(1);
    expect(p.run).not.toHaveBeenCalled();
  });
it("does not replay a failed loader", async () => {
  const load = vi.fn(async () => {
      throw Error("OWNED_MODULE_UNAVAILABLE");
    }),
    d = new DeferredPlugin(moduleMetadata("baseline"), load);
  await expect(d.run(context())).rejects.toThrow("OWNED_MODULE_UNAVAILABLE");
  await expect(d.run(context())).rejects.toThrow("OWNED_MODULE_UNAVAILABLE");
  expect(load).toHaveBeenCalledTimes(1);
});
