// @vitest-environment jsdom
import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdvancedEngineStudio, advancedEngineRequestValues, type AdvancedEngineDraft, type AdvancedEngineId } from "./AdvancedEngineStudio";

afterEach(() => vi.unstubAllGlobals());

describe("advanced engine studio", () => {
  it("uses a guided inline builder and authoritative field validation as the primary workflow", async () => {
    const calls: Array<{ url: string; body?: any }> = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input); calls.push({ url, ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) });
      const body = url.includes("/catalog") ? { engines: [{ id: "supabase-authorization", displayName: "Supabase / PostgREST / RLS / Storage", description: "Actor matrix", moduleId: "supabase-authorization", requestField: "supabaseAuthorization", safety: "No inline keys.", requiresApproval: true, template: { schemaVersion: 1, projectUrl: "https://app.example.test", anonKeyEnv: "SUPABASE_ANON_KEY", maxCases: 10, maxResponseBytes: 8192, maxSignedUrlBytes: 4096, cases: [{ id: "anon-denied", surface: "TABLE", resource: "public.documents", operation: "SELECT", actor: "ANONYMOUS", expectedDecision: "DENY", boundary: "NONE", method: "GET", url: "/rest/v1/documents", headers: {}, responseShape: "LIST", identityAssertions: [], forbiddenColumns: [], requireVerifiedIdentity: false }], catalog: { exposedSchemas: ["public"], expectedExposedSchemas: ["public"], tables: [], functions: [], storageBuckets: [], relationships: [] } } }] } : { valid: true, diagnostics: [] };
      return { ok: true, status: 200, json: async () => body } as Response;
    }));
    let drafts: AdvancedEngineDraft[] = [];
    const Wrapper = () => { const [value, setValue] = React.useState(drafts); drafts = value; return <AdvancedEngineStudio target="https://app.example.test" drafts={value} selectedModules={[]} onChange={setValue} onEnableModule={() => undefined} onPreview={async () => undefined} />; };
    const user = userEvent.setup(); render(<Wrapper />);
    await user.click(await screen.findByRole("button", { name: "Configure" }));
    expect(screen.getByRole("region", { name: /Supabase.*builder/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Guided builder" }).className).toContain("selected");
    expect(screen.queryByText("Explicit manifest path")).toBeNull();
    const projectUrl = screen.getByLabelText("Project Url");
    await user.clear(projectUrl); await user.type(projectUrl, "https://project.example.test");
    await user.click(screen.getByRole("button", { name: "Validate fields" }));
    expect(calls.some((call) => call.url.includes("/validate") && call.body.engineId === "supabase-authorization" && call.body.value.projectUrl === "https://project.example.test")).toBe(true);
    expect(drafts[0]?.value.projectUrl).toBe("https://project.example.test");
  });

  it("maps every enabled builder to its inline planner contract and splits pre-handover authorization", () => {
    const ids: AdvancedEngineId[] = ["supabase-authorization", "authentication-lifecycle", "authentication-lifecycle-automation", "business-invariant", "controlled-race", "api-graphql-authorization", "link-portal-export-security", "operational-endpoint-security", "billing-entitlement-security", "assisted-review", "pre-handover-assault", "bug-bounty-authorization", "active-vulnerability-validation"];
    const drafts = ids.map((id) => ({ id, enabled: id !== "bug-bounty-authorization", editorMode: "guided" as const, value: id === "pre-handover-assault" ? { orchestration: { schemaVersion: 1 }, authorization: { schemaVersion: 1 } } : { schemaVersion: 1 } }));
    const result = advancedEngineRequestValues(drafts);
    expect(Object.keys(result).sort()).toEqual(["activeVulnerability", "apiGraphql", "assistedReview", "authenticationLifecycle", "authenticationLifecycleAutomation", "billingEntitlement", "businessInvariant", "controlledRace", "linkPortalSecurity", "operationalEndpointSecurity", "preHandover", "supabaseAuthorization", "targetAuthorization"].sort());
    expect(result.preHandover).toEqual({ schemaVersion: 1 });
    expect(result.targetAuthorization).toEqual({ schemaVersion: 1 });
  });
});
