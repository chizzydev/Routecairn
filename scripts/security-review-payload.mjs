import { readFile } from "node:fs/promises";
import { canonicalReviewPayload, reviewSchema } from "./security-review-contract.mjs";
const index = process.argv.indexOf("--input");
const input = index >= 0 ? process.argv[index + 1] : undefined;
if (!input) throw new Error("Pass --input security-reviews/vX.Y.Z.review.json.");
const attestation = reviewSchema.parse(JSON.parse(await readFile(input, "utf8")));
process.stdout.write(canonicalReviewPayload(attestation));
