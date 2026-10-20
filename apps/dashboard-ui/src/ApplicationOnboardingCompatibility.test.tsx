// @vitest-environment jsdom
import React from "react";
import { it, expect, afterEach, vi } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { ApplicationOnboardingCompatibility } from "./ApplicationOnboardingCompatibility";
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
it("explains actual tenantless, side-effect and unavailable-profile blockers without network or credentials", () => {
  const fetch = vi.fn(() => {
    throw Error("UNAUTHORIZED_NETWORK");
  });
  vi.stubGlobal("fetch", fetch);
  render(<ApplicationOnboardingCompatibility />);
  expect(screen.getByText("Compatibility: INCOMPLETE")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Verified tenant identity exists"), { target: { value: "ABSENT" } });
  fireEvent.change(screen.getByLabelText("GET handler and middleware effects"), { target: { value: "WRITES" } });
  fireEvent.change(screen.getByLabelText("Legitimate target-bound actor profiles"), {
    target: { value: "INSUFFICIENT" }
  });
  expect(screen.getByText("Compatibility: BLOCKED")).toBeTruthy();
  expect(screen.getByText(/Do not substitute user IDs/)).toBeTruthy();
  expect(screen.getByText(/GET middleware or handlers write state/)).toBeTruthy();
  expect(screen.queryByRole("button")).toBeNull();
  expect(document.querySelector('input[type="password"]')).toBeNull();
  expect(fetch).not.toHaveBeenCalled();
});
it("updating declarations never promotes them to verified or execution-approved status", () => {
  render(<ApplicationOnboardingCompatibility />);
  const values = ["PRESENT", "THREE_DISTINCT", "READ_ONLY", "CONFIRMED", "SCALAR_MARKERS"];
  screen.getAllByRole("combobox").forEach((select, i) => fireEvent.change(select, { target: { value: values[i] } }));
  expect(screen.getByText("Compatibility: DECLARED_COMPATIBLE_REVIEW_REQUIRED")).toBeTruthy();
  expect(screen.getByText(/not saved authorization, native proof/)).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Ownership observation shape"), { target: { value: "COLLECTION_ONLY" } });
  expect(screen.getByText("Compatibility: BLOCKED")).toBeTruthy();
});
