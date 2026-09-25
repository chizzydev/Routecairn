import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runProtocolAcceptance } from "../../src/validation/ProtocolAcceptance.js";

describe("protocol acceptance laboratory", () => {
  it("executes authorization, streaming, cleanup, TLS, gRPC, and native HTTP/3 fixtures", async () => {
    const directory = await mkdtemp(join(tmpdir(), "routecairn-protocol-fixtures-"));
    const summary = await runProtocolAcceptance(directory);
    expect(summary).toMatchObject({ status: "PASSED", nativeHttp3: true, externalCurlRequired: false });
    expect(summary.lanes.map((lane) => lane.name)).toEqual(["websocket-authorization", "graphql-websocket", "multipart-cleanup", "grpc-tls", "http2-tls", "http3-native"]);
    expect(summary.lanes.every((lane) => lane.status === "PASSED")).toBe(true);
    expect(summary.lanes.find((lane) => lane.name === "graphql-websocket")?.checks).toMatchObject({ deniedRejected: true, modernData: true, legacyData: true });
    expect(summary.lanes.find((lane) => lane.name === "multipart-cleanup")?.checks).toMatchObject({ deniedCleanupStatus: 401, restored: true });
    expect(summary.lanes.find((lane) => lane.name === "grpc-tls")?.checks).toMatchObject({ protocol: "h2", deniedGrpcStatus: 7, unaryMessages: 1, streamMessages: 2, trailersVerified: true });
    expect(summary.lanes.find((lane) => lane.name === "http3-native")?.checks).toMatchObject({ protocol: "h3", sameConnection: true, externalCurlRequired: false });
    const evidence = await readFile(join(summary.outputDirectory, "protocol-acceptance.json"), "utf8");
    for (const secret of ["websocket-fixture-token", "graphql-fixture-token", "cleanup-fixture-token", "grpc-fixture-token", "h2-fixture-token", "h3-fixture-token"]) expect(evidence).not.toContain(secret);
  }, 300_000);
});
