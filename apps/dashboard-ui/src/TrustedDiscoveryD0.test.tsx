// @vitest-environment jsdom
import React from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "./main";
import { setActiveOrganizationId, setCsrfToken } from "./api";
afterEach(() => { cleanup(); vi.unstubAllGlobals(); setActiveOrganizationId(""); setCsrfToken(""); });
function loginTransport(defer = false) {
  let authenticated = false, release!: (value: Response) => void;
  const org = "11111111-1111-4111-8111-111111111111";
  const response = (body: unknown, status = 200) => ({ status, ok: status === 200, json: async () => body }) as Response;
  const fetch = vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path === "/api/auth/login") { authenticated = true; return response({ csrfToken: "fixture-csrf", user: { role: "OWNER", login: "copied-login-payload" } }); }
    if (!authenticated) return response({ error: "Dashboard session required." }, 401);
    if (path === "/api/operations/organizations") return defer ? new Promise<Response>((done) => { release = done; }) : response({ organizations: [{ id: org, name: "Native selected organization", role: "OWNER" }] });
    if (path === "/api/auth/session") return response({ principal: { role: "OWNER", login: "native-session" } });
    if (path === "/api/auth/csrf") return response({ csrfToken: "fixture-csrf" });
    return response({ scans: {}, findings: {}, recentScans: [] });
  }); vi.stubGlobal("fetch", fetch); return { fetch, org, release: () => release(response({ organizations: [{ id: org, name: "Native selected organization", role: "OWNER" }] })) };
}
async function signIn() { const user = userEvent.setup(); await user.type(await screen.findByLabelText("Username or email"), "fixture"); await user.type(screen.getByLabelText("Password"), "fixture-password"); await user.click(screen.getByRole("button", { name: /^Log In$/ })); }
it("D0 login must revalidate native session and populate organizations without manual reload", async () => {
  const f = loginTransport(); render(<App />); await signIn();
  expect(await screen.findByLabelText("Active organization")).toBeTruthy();
  expect((screen.getByLabelText("Active organization") as HTMLSelectElement).value).toBe(f.org);
  expect(screen.getByText(/native-session/)).toBeTruthy(); expect(screen.queryByText(/copied-login-payload/)).toBeNull();
});
it("D0 an organization response after unmount cannot persist stale selected authority", async () => {
  const f = loginTransport(true); const view = render(<App />); await signIn();
  await waitFor(() => expect(f.fetch.mock.calls.some(([path]) => String(path) === "/api/operations/organizations")).toBe(true));
  view.unmount(); f.release(); await Promise.resolve();
  expect(window.sessionStorage.getItem("routecairn.active-organization")).not.toBe(f.org);
});
