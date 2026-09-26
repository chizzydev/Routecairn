import { readFile } from "node:fs/promises";
import type { Command } from "commander";
import { generateExternalAcceptanceKeyPair, loadExternalAcceptanceManifest, runExternalAcceptance, verifyExternalAcceptanceBundle } from "../../validation/ExternalAcceptance.js";

export function registerValidateBroaderExternalCommand(program: Command): void {
  const command = program.command("external-acceptance").description("Run, sign, and verify release-bound third-party acceptance evidence.");

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
    .action(async (options: { manifest: string; releaseArtifact: string; signingKeyEnv: string; output?: string }) => {
      const signingKey = process.env[options.signingKeyEnv];
      if (!signingKey) throw new Error(`EXTERNAL_ACCEPTANCE_SIGNING_KEY_MISSING:${options.signingKeyEnv}`);
      const manifest = await loadExternalAcceptanceManifest(options.manifest);
      const bundle = await runExternalAcceptance(manifest, { releaseArtifact: options.releaseArtifact, signingKey, ...(options.output ? { outputDirectory: options.output } : {}) });
      process.stdout.write(`${JSON.stringify({ status: bundle.summary.status, outputDirectory: bundle.summary.outputDirectory, evidenceSha256: bundle.summary.evidenceSha256, keyId: bundle.summary.operator.publicKeyId, releaseSha256: bundle.summary.artifact.sha256 }, null, 2)}\n`);
      if (bundle.summary.status !== "PASSED") process.exitCode = 2;
    });

  command.command("verify")
    .description("Verify a published bundle against an independently obtained public key and exact release artifact.")
    .requiredOption("--bundle <file>", "Published external-acceptance-bundle.json.")
    .requiredOption("--release-artifact <file>", "Exact release artifact covered by the attestation.")
    .requiredOption("--trusted-public-key <file>", "Independently obtained operator public key.")
    .requiredOption("--manifest <file>", "Exact credential-free manifest published with the bundle.")
    .action(async (options: { bundle: string; releaseArtifact: string; trustedPublicKey: string; manifest: string }) => {
      await readFile(options.trustedPublicKey, "utf8");
      process.stdout.write(`${JSON.stringify(await verifyExternalAcceptanceBundle(options.bundle, options.releaseArtifact, options.trustedPublicKey, options.manifest), null, 2)}\n`);
    });
}
