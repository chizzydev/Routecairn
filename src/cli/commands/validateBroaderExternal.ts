import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import type { Command } from "commander";
import { assertCredentialReferences, generateExternalAcceptanceKeyPair, loadExternalAcceptanceManifest, runExternalAcceptance, validateNpmReleaseArtifact, verifyExternalAcceptanceBundle } from "../../validation/ExternalAcceptance.js";
import { acceptanceDigest, externalAcceptanceBindingsSchema, externalAcceptanceTrustSchema, prepareExternalAcceptance } from "../../validation/ExternalAcceptanceReadiness.js";
import { retainOwnedDecideAcceptance } from "../../validation/OwnedAcceptanceHistory.js";
import { exerciseOwnedDecide, ownedDecideAuthorizationSchema } from "../../validation/OwnedDecideExercise.js";
import { decideRecoverySchema, openDecideAcceptanceAccounts } from "../../validation/DecideAcceptanceAccounts.js";
import { exerciseOwnedSupabase, recoverOwnedSupabase, ownedSupabaseAuthorizationSchema, supabasePrivateCredentialsSchema } from "../../validation/OwnedSupabaseExercise.js";
import { openSupabaseAcceptanceStore, supabaseRecoverySchema } from "../../validation/SupabaseAcceptanceStore.js";

export function registerValidateBroaderExternalCommand(program: Command): void {
  const command = program.command("external-acceptance").description("Run, sign, and verify release-bound third-party acceptance evidence.");
  for (const recovering of [false, true]) {
    const subcommand = command.command(recovering ? "recover-supabase" : "exercise-supabase").description(recovering ? "Clean only exact isolated hosted Supabase resources from a private recovery journal." : "Exercise hosted Supabase Auth, RLS, private Storage and RPC with two disposable identities.")
      .requiredOption("--authorization <file>").requiredOption("--credentials <file>").requiredOption("--decide-api-directory <directory>")
      .option("--environment-file <file>").requiredOption("--database-ca <file>");
    if (recovering) subcommand.requiredOption("--recovery <file>"); else subcommand.requiredOption("--output <directory>");
    subcommand.action(async (options: { authorization: string; credentials: string; decideApiDirectory: string; environmentFile?: string; databaseCa: string; recovery: string; output: string }) => {
      const authorization = ownedSupabaseAuthorizationSchema.parse(JSON.parse(await readFile(options.authorization, "utf8")));
      const credentials = supabasePrivateCredentialsSchema.parse(JSON.parse(await readFile(options.credentials, "utf8")));
      const database = await openSupabaseAcceptanceStore({ apiDirectory: options.decideApiDirectory, databaseCaFile: options.databaseCa, projectRef: authorization.projectRef, ...(options.environmentFile ? { environmentFile: options.environmentFile } : {}) });
      try {
        if (recovering) {
          const recovery = supabaseRecoverySchema.parse(JSON.parse(await readFile(options.recovery, "utf8")));
          const result = await recoverOwnedSupabase(recovery, authorization, credentials, database.store);
          if (result.status === "VERIFIED") await writeFile(options.recovery, `${JSON.stringify({ ...recovery, stage: "CLEANUP_VERIFIED" }, null, 2)}\n`, { mode: 0o600 });
          await writeFile(resolve(dirname(options.recovery), "owned-supabase-recovery.json"), `${JSON.stringify({ schemaVersion: 1, standard: "OWNED_SUPABASE_RECOVERY_V1", runId: recovery.runId, checkedAt: new Date().toISOString(), authorizationSha256: acceptanceDigest(Buffer.from(JSON.stringify(authorization))), ...result, independentAcceptanceVerified: false }, null, 2)}\n`, { mode: 0o600 });
          process.stdout.write(`${JSON.stringify({ cleanup: result.status, remaining: result.remaining, failures: result.failures })}\n`);
          if (result.status !== "VERIFIED") process.exitCode = 2;
        } else {
          const result = await exerciseOwnedSupabase(authorization, credentials, database.store, options.output);
          process.stdout.write(`${JSON.stringify({ directory: result.directory, status: result.evidence.status, requests: result.evidence.requestCount, cleanup: result.evidence.cleanup, failedCases: result.evidence.receipts.filter((item) => item.status === "FAILED").map((item) => item.case), pendingObservations: result.evidence.receipts.filter((item) => item.status === "PENDING").map((item) => item.case), primaryError: result.evidence.primaryError, independentAcceptanceVerified: false }, null, 2)}\n`);
          if (result.evidence.status !== "PASSED") process.exitCode = 2;
        }
      } finally { await database.close(); }
    });
  }
  command.command("exercise-decide").description("Provision two disposable owned Decide accounts, exercise account/session contracts, and verify cleanup.")
    .requiredOption("--authorization <file>").requiredOption("--decide-api-directory <directory>").option("--environment-file <file>")
    .requiredOption("--database-ca <file>").requiredOption("--output <directory>")
    .action(async (options: { authorization: string; decideApiDirectory: string; environmentFile?: string; databaseCa: string; output: string }) => {
      const authorization = ownedDecideAuthorizationSchema.parse(JSON.parse(await readFile(options.authorization, "utf8")));
      const database = await openDecideAcceptanceAccounts({ apiDirectory: options.decideApiDirectory, databaseCaFile: options.databaseCa, ...(options.environmentFile ? { environmentFile: options.environmentFile } : {}) });
      try {
        const result = await exerciseOwnedDecide(authorization, database.store, options.output);
        process.stdout.write(`${JSON.stringify({ directory: result.directory, status: result.evidence.status, requests: result.evidence.requestCount, cleanup: result.evidence.cleanup, failedCases: result.evidence.receipts.filter((item) => item.status !== "PASSED").map((item) => item.case), independentAcceptanceVerified: false }, null, 2)}\n`);
        if (result.evidence.status !== "PASSED") process.exitCode = 2;
      } finally { await database.close(); }
    });
  command.command("recover-decide").description("Remove only the exact disposable identities in an interrupted owned Decide recovery journal.")
    .requiredOption("--recovery <file>").requiredOption("--decide-api-directory <directory>").option("--environment-file <file>").requiredOption("--database-ca <file>")
    .action(async (options: { recovery: string; decideApiDirectory: string; environmentFile?: string; databaseCa: string }) => {
      const recovery = decideRecoverySchema.parse(JSON.parse(await readFile(options.recovery, "utf8")));
      const database = await openDecideAcceptanceAccounts({ apiDirectory: options.decideApiDirectory, databaseCaFile: options.databaseCa, ...(options.environmentFile ? { environmentFile: options.environmentFile } : {}) });
      try {
        await database.store.remove(recovery.accounts); const remaining = await database.store.remaining(recovery.accounts);
        const verified = remaining.users === 0 && remaining.sessions === 0;
        if (verified) await writeFile(options.recovery, `${JSON.stringify({ ...recovery, stage: "CLEANUP_VERIFIED" }, null, 2)}\n`, { mode: 0o600 });
        process.stdout.write(`${JSON.stringify({ cleanup: verified ? "VERIFIED" : "FAILED", remaining })}\n`);
        if (!verified) process.exitCode = 2;
      } finally { await database.close(); }
    });
  command.command("retain-decide-history").description("Retain secret-free owned-target history; optionally check explicitly approved public origins.")
    .requiredOption("--source-directory <directory>").requiredOption("--output <directory>").option("--probe-approved-origins <origins...>")
    .action(async (options: { sourceDirectory: string; output: string; probeApprovedOrigins?: string[] }) => {
      process.stdout.write(`${JSON.stringify(await retainOwnedDecideAcceptance({ sourceDirectory: options.sourceDirectory, outputDirectory: options.output, ...(options.probeApprovedOrigins ? { probeApprovedOrigins: options.probeApprovedOrigins } : {}) }), null, 2)}\n`);
    });

  command.command("prepare").description("Check actual operator, authorization, deployment and reproduction inputs without sending provider requests.")
    .requiredOption("--manifest <file>").option("--release-artifact <file>").option("--bindings <file>").option("--trust <file>").option("--resolve-dns", "Resolve approved origins; no HTTP requests are sent.").requiredOption("--output <file>")
    .action(async (options: { manifest: string; releaseArtifact?: string; bindings?: string; trust?: string; resolveDns?: boolean; output: string }) => {
      const manifest = await loadExternalAcceptanceManifest(options.manifest);
      const bindings = options.bindings ? externalAcceptanceBindingsSchema.parse(JSON.parse(await readFile(options.bindings, "utf8"))) : undefined;
      const trust = options.trust ? externalAcceptanceTrustSchema.parse(JSON.parse(await readFile(options.trust, "utf8"))) : undefined;
      const readiness = await prepareExternalAcceptance(manifest, { ...(bindings ? { bindings } : {}), ...(trust ? { trust } : {}), resolveDns: options.resolveDns ?? false });
      try { assertCredentialReferences(manifest); } catch { readiness.issues.push({ code: "INLINE_CREDENTIAL_FORBIDDEN", location: "manifest" }); }
      try { if (!options.releaseArtifact) throw new Error(); const artifact = await readFile(options.releaseArtifact); validateNpmReleaseArtifact(artifact, manifest.release.version); if (acceptanceDigest(artifact) !== manifest.release.artifactSha256) throw new Error(); } catch { readiness.issues.push({ code: "RELEASE_ARTIFACT_UNVERIFIED", location: "release" }); }
      if (readiness.issues.length) { readiness.status = "BLOCKED"; for (const lane of readiness.lanes) lane.status = "BLOCKED"; }
      const path = resolve(options.output); await mkdir(dirname(path), { recursive: true }); await writeFile(path, `${JSON.stringify(readiness, null, 2)}\n`, { mode: 0o600 });
      process.stdout.write(`${JSON.stringify({ status: readiness.status, output: path, issueCount: readiness.issues.length, externalAcceptancePerformed: false }, null, 2)}\n`);
      if (readiness.status === "BLOCKED") process.exitCode = 2;
    });

  command.command("keygen")
    .description("Generate an Ed25519 acceptance-publisher key pair without overwriting existing keys.")
    .requiredOption("--private-key <file>", "Private PKCS#8 PEM output path.")
    .requiredOption("--public-key <file>", "Public SPKI PEM output path.")
    .action(async (options: { privateKey: string; publicKey: string }) => {
      process.stdout.write(`${JSON.stringify(await generateExternalAcceptanceKeyPair(options.privateKey, options.publicKey), null, 2)}\n`);
    });

  command.command("run")
    .description("Execute the exact eight-lane manifest and publish a signed in-toto/DSSE evidence bundle.")
    .requiredOption("--manifest <file>", "Authorized external-acceptance manifest.")
    .requiredOption("--release-artifact <file>", "Exact RouteCairn release artifact named in the manifest.")
    .requiredOption("--signing-key-env <name>", "Environment variable containing the publisher private PEM or base64 DER.")
    .option("--output <directory>", "Parent directory for immutable run evidence.")
    .option("--bindings <file>", "Digest-bound owner approval, reproduction and deployment files.")
    .option("--trust <file>", "Independently administered operator trust registry.")
    .option("--fixture", "Explicit loopback-only engineering run; cannot establish independent acceptance.")
    .action(async (options: { manifest: string; releaseArtifact: string; signingKeyEnv: string; output?: string; bindings?: string; trust?: string; fixture?: boolean }) => {
      const signingKey = process.env[options.signingKeyEnv];
      if (!signingKey) throw new Error(`EXTERNAL_ACCEPTANCE_SIGNING_KEY_MISSING:${options.signingKeyEnv}`);
      const manifest = await loadExternalAcceptanceManifest(options.manifest);
      const bundle = await runExternalAcceptance(manifest, { releaseArtifact: options.releaseArtifact, signingKey, mode: options.fixture ? "FIXTURE" : "INDEPENDENT_EXTERNAL", ...(options.bindings ? { bindingsPath: options.bindings } : {}), ...(options.trust ? { trustPath: options.trust } : {}), ...(options.output ? { outputDirectory: options.output } : {}) });
      process.stdout.write(`${JSON.stringify({ status: bundle.summary.status, outputDirectory: bundle.summary.outputDirectory, evidenceSha256: bundle.summary.evidenceSha256, keyId: bundle.summary.operator.publicKeyId, releaseSha256: bundle.summary.artifact.sha256 }, null, 2)}\n`);
      if (bundle.summary.status !== "PASSED") process.exitCode = 2;
    });

  command.command("verify")
    .description("Verify a published bundle against an independently obtained public key and exact release artifact.")
    .requiredOption("--bundle <file>", "Published external-acceptance-bundle.json.")
    .requiredOption("--release-artifact <file>", "Exact release artifact covered by the attestation.")
    .requiredOption("--trusted-public-key <file>", "Independently obtained operator public key.")
    .requiredOption("--manifest <file>", "Exact credential-free manifest published with the bundle.")
    .option("--bindings <file>").option("--trust <file>").option("--allow-fixture", "Verify a fixture signature without claiming independent acceptance.")
    .action(async (options: { bundle: string; releaseArtifact: string; trustedPublicKey: string; manifest: string; bindings?: string; trust?: string; allowFixture?: boolean }) => {
      await readFile(options.trustedPublicKey, "utf8");
      const result = await verifyExternalAcceptanceBundle(options.bundle, options.releaseArtifact, options.trustedPublicKey, options.manifest, { ...(options.bindings ? { bindingsPath: options.bindings } : {}), ...(options.trust ? { trustPath: options.trust } : {}) });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      if (result.status !== "PASSED" || !result.independentAcceptanceVerified && !options.allowFixture) process.exitCode = 2;
    });
}
