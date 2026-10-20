// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { ApplicationTransitionPanel } from "./ApplicationTransitionPanel";
import type { ApplicationHypothesisService } from "../../../src/dashboard/execution/ApplicationHypothesisService";
vi.mock("./api", () => ({ apiMutation: vi.fn(), apiGet: vi.fn() }));
afterEach(cleanup);
type Proposal = ReturnType<ApplicationHypothesisService["generate"]>;
const base = {
  proposalId: "proposal",
  source: { targetId: "target", mapRevisionId: "after" },
  flow: { name: "Owned flow", steps: [{ routeId: "source" }, { routeId: "operation" }] }
} as unknown as Proposal;
const signed = (eligibility: string) =>
  ({
    ...base,
    transition: {
      eligibility,
      policyOutcome: eligibility === "ABSTAIN" ? "INCONCLUSIVE" : "PROPOSED_LEGITIMATE_REQUIRES_AUTHORITY_REVIEW",
      eventEvidence: "SIGNATURE_VALID_AUTHORITY_UNCONFIRMED",
      beforeSource: { mapRevisionId: "before", sourceScanId: "scan1", sourceHash: "hash1" },
      afterSource: { mapRevisionId: "after", sourceScanId: "scan2", sourceHash: "hash2" },
      declaration: {
        authorityKeySha256: "a".repeat(64),
        purpose: "Observe the pinned post-state without changing the application.",
        policy: "LEGITIMATE",
        event: {
          eventId: "event",
          actorId: "primary",
          role: "reviewer",
          statePath: "phase",
          beforeState: 1,
          afterState: 2,
          fromRevision: 1,
          toRevision: 2
        }
      },
      missingControls: eligibility === "ABSTAIN" ? ["AFTER_EXACT_TYPED_PRE_POSTCONDITION_REQUIRED"] : [],
      keyAuthority: "EXPLICIT_HUMAN_TRUST_REQUIRED",
      causality: "CORRELATION_NOT_CAUSAL_PROOF"
    }
  }) as unknown as Proposal;
it("keeps draft transmission unavailable to read-only users", () => {
  render(<ApplicationTransitionPanel proposal={base} canExecute={false} onProposal={vi.fn()} onReview={vi.fn()} />);
  expect(
    screen.getByRole("button", { name: "Draft reviewed state-transition contract" }).hasAttribute("disabled")
  ).toBe(true);
  expect(screen.getByLabelText("Signed target event JSON").hasAttribute("disabled")).toBe(true);
  expect(screen.queryByText("Authorize and run selected matrix")).toBeNull();
});
it("requires independently trusted authority and purpose/consent for every exact observation", () => {
  const onReview = vi.fn();
  render(
    <ApplicationTransitionPanel
      proposal={signed("EVIDENCE_READY_FOR_POLICY_REVIEW")}
      canExecute
      onProposal={vi.fn()}
      onReview={onReview}
    />
  );
  fireEvent.click(screen.getByLabelText("I independently trust this exact target event key"));
  for (const c of screen.getAllByRole("checkbox").slice(1)) fireEvent.click(c);
  const r = onReview.mock.calls.at(-1)![0];
  expect(r.authorityConfirmed).toBe(true);
  expect(r.checks).toHaveLength(8);
  expect(r.checks.every((c: { consent: boolean; purpose: string }) => c.consent && c.purpose.length >= 10)).toBe(true);
  fireEvent.change(screen.getByLabelText("Transition check purpose source:primary"), {
    target: { value: "A changed human observation purpose" }
  });
  expect(onReview.mock.calls.at(-1)![0]).toBeUndefined();
});
it("cannot promote incomplete evidence by human checkboxes", () => {
  const onReview = vi.fn();
  render(
    <ApplicationTransitionPanel proposal={signed("ABSTAIN")} canExecute onProposal={vi.fn()} onReview={onReview} />
  );
  for (const c of screen.getAllByRole("checkbox")) {
    expect(c.hasAttribute("disabled")).toBe(true);
    fireEvent.click(c);
  }
  expect(onReview.mock.calls.some((v) => v[0] !== undefined)).toBe(false);
  expect(screen.getByText("AFTER_EXACT_TYPED_PRE_POSTCONDITION_REQUIRED")).toBeTruthy();
});
