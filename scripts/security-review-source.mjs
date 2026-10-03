import { execFileSync } from "node:child_process";

export function verifyReviewedSource(review, { cwd = process.cwd() } = {}) {
  const git = (...args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  if (git("status", "--porcelain", "--untracked-files=normal")) throw new Error("Review verification requires a clean working tree.");
  git("merge-base", "--is-ancestor", review.sourceCommit, "HEAD");
  const allowed = new Set([`security-reviews/${review.release}.review.json`, review.reportPath]);
  const changed = git("diff", "--name-only", "--no-renames", review.sourceCommit, "HEAD").split("\n").filter(Boolean);
  if (changed.some((file) => !allowed.has(file))) throw new Error("Release contains source changes after the reviewed commit.");
  for (const file of allowed) if (!git("ls-files", "--", file)) throw new Error("Review evidence must be committed.");
}
