import { it, expect } from "vitest";
import { randomUUID, createHash } from "node:crypto";
import { businessFlowFixture } from "../helpers/businessflow-fixture.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
import { ApplicationAnalystHandoff } from "../../src/dashboard/execution/ApplicationAnalystHandoff.js";
it("paginates complete retained membership, exposes old UNKNOWN, rejects stale continuation and exports no free text", async () => {
  const f = await businessFlowFixture("orders");
  try {
    const a = await f.acquire(f.input),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
      d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
    if (!d.matrix) throw Error("MATRIX");
    const clone = f.database.db.prepare(
      "INSERT INTO authorization_workbench_revisions SELECT ?,organization_id,target_id,?,source_scan_id,input_json,request_json,context_digest,digest,preview_identity,created_by,?,expires_at,review_json FROM authorization_workbench_revisions WHERE id=?"
    );
    const unknown = randomUUID();
    f.database.db
      .transaction(() => {
        for (let i = 0; i < 104; i++)
          clone.run(
            i === 0 ? unknown : randomUUID(),
            i + 2,
            new Date(Date.now() + i).toISOString(),
            d.matrix!.revisionId
          );
        f.database.db
          .prepare("INSERT INTO authorization_workbench_dispatches VALUES(?,?,?)")
          .run(unknown, "operator", new Date().toISOString());
      })
      .immediate();
    const triage = new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench),
      service = new ApplicationAnalystHandoff(f.database, triage, f.workbench),
      first = service.page(f.org, p.proposalId, {}),
      ids: string[] = [],
      pages: unknown[] = [];
    let page: ReturnType<typeof service.page> | undefined = first;
    while (page) {
      ids.push(...page.entries.map((e) => e.id));
      pages.push(page);
      page = page.nextCursor ? service.page(f.org, p.proposalId, { cursor: page.nextCursor }) : undefined;
    }
    expect(ids).toHaveLength(105);
    expect(new Set(ids).size).toBe(105);
    const search = service.page(f.org, p.proposalId, { query: "UNKNOWN" });
    expect(search.entries[0]!.id).toBe(unknown);
    expect(search.entries[0]!.detail).toMatchObject({ status: "UNKNOWN" });
    const current = triage.get(f.org, p.proposalId);
    triage.note(
      f.org,
      p.proposalId,
      {
        digest: current.digest,
        disposition: "NEEDS_OWNER_CONTEXT",
        rationale: "Unstructured sensitive owner words are deliberately omitted from the analyst export.",
        reviewConfirmed: true
      },
      "operator"
    );
    const packet = service.export(f.org, p.proposalId),
      { packetSha256, integrityMeaning: _meaning, ...body } = packet;
    expect(createHash("sha256").update(JSON.stringify(body)).digest("hex")).toBe(packetSha256);
    expect(packet.proofIndex.some((r) => r.id === unknown && r.state === "UNKNOWN")).toBe(true);
    expect(packet.historyIncomplete).toBe(true);
    expect(JSON.stringify(packet)).not.toContain("Unstructured sensitive");
    clone.run(randomUUID(), 106, new Date(Date.now() + 9999).toISOString(), d.matrix.revisionId);
    expect(() => service.page(f.org, p.proposalId, { cursor: first.nextCursor! })).toThrow("HISTORY_CHANGED");
    expect(() => service.page("other-org", p.proposalId, {})).toThrow();
    f.capture("ANALYST_HANDOFF_PAGINATION", { pages, search, packet, sql: f.database.db.pragma("integrity_check") });
  } finally {
    await f.close();
  }
});
