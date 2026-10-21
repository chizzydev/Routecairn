import { expect, it } from "vitest";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it.each([401, 403])("reports native %s as observed denial, never successful authentication", async (status) => {
  const f = await flexibleFixture(1, { noIdentity: true, revoked: true, denialStatus: status } as Parameters<
    typeof flexibleFixture
  >[1]);
  try {
    const r = await f.run();
    const w = r.report.assessmentCapabilities.workflows.find(
      (w: { workflowId: string }) => w.workflowId === "observeactor0"
    );
    expect(w.reason).toBe("NATIVE_AUTHENTICATED_REQUEST_DENIED_NOT_SESSION_SUCCESS");
    expect(w.authenticationResult).toBe("DENIED");
    expect(w.evidence[0].responseStatuses).toEqual([status]);
  } finally {
    await f.close();
  }
});
