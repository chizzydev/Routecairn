import { it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
it("runs the public offline minimizer against owned files, retains redacted output and refuses overwrite", () => {
  const root = createOwnedTestDirectory("offline-minimizer-cli");
  try {
    const url = "http://127.0.0.1:8099/record/7",
      metadata = {
        version: 1,
        origin: "http://127.0.0.1:8099",
        provenance: "OWNER_LOCAL_APPLICATION",
        routes: [
          { id: "record", kind: "OBJECT", method: "GET", url, pathTemplate: "/record/7", identityPath: "record.id" }
        ],
        actors: ["primary", "account_a", "account_b"].map((slot) => ({
          slot,
          principalFingerprint: "1".repeat(16),
          tenantFingerprint: "2".repeat(16),
          roleFingerprint: "3".repeat(16),
          sessionEvidenceSha256: "a".repeat(64)
        }))
      };
    writeFileSync(
      join(root, "in.har"),
      JSON.stringify({
        log: {
          entries: [
            {
              startedDateTime: new Date().toISOString(),
              request: {
                method: "GET",
                url,
                headers: [{ name: "Authorization", value: "Bearer synthetic-offline-secret" }]
              }
            }
          ]
        }
      }),
      { flag: "wx" }
    );
    writeFileSync(join(root, "metadata.json"), JSON.stringify(metadata), { flag: "wx" });
    const args = [
        "--import",
        "tsx",
        resolve("scripts/prepare-owned-intake.ts"),
        "--i-own-this-offline-export",
        join(root, "in.har"),
        join(root, "metadata.json"),
        join(root, "out.json")
      ],
      run = spawnSync(process.execPath, args, { windowsHide: true, encoding: "utf8" }),
      before = readFileSync(join(root, "out.json")),
      replay = spawnSync(process.execPath, args, { windowsHide: true, encoding: "utf8" });
    writeFileSync(
      join(root, "CLI_RECEIPTS.json"),
      JSON.stringify({ run, replay, args, notIndependentlySupplied: true }),
      { flag: "wx" }
    );
    expect(run.status).toBe(0);
    expect(before.toString()).not.toContain("synthetic-offline-secret");
    expect(replay.status).not.toBe(0);
    expect(readFileSync(join(root, "out.json")).equals(before)).toBe(true);
  } finally {
    retainOwnedTestDirectory(root);
  }
});
