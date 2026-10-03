import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";

const index = process.argv.indexOf("--tag");
const tag = process.argv[index + 1];
const version = JSON.parse(await readFile("package.json", "utf8")).version;
if (index < 0 || tag !== `v${version}`) throw new Error("Pass the exact versioned release tag.");
const repository = process.env.GITHUB_REPOSITORY;
if (!repository?.match(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u)) throw new Error("A GitHub repository identity is required.");
const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const api = (suffix) => JSON.parse(execFileSync("gh", ["api", `repos/${repository}/${suffix}`], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 }));
const ref = api(`git/ref/tags/${tag}`);
if (ref.object?.type !== "tag") throw new Error("Release tag must be annotated and signed.");
const annotated = api(`git/tags/${ref.object.sha}`);
if (!annotated.verification?.verified || annotated.object?.type !== "commit" || annotated.object.sha !== commit) throw new Error("Release tag signature or source binding is invalid.");
const required = ["continuous-assurance.yml", "codeql.yml"];
for (const workflow of required) {
  const data = api(`actions/workflows/${workflow}/runs?head_sha=${commit}&per_page=100`);
  const runs = data.workflow_runs.filter((run) => run.head_sha === commit && ["push", "workflow_dispatch"].includes(run.event)).sort((a, b) => b.id - a.id);
  if (!runs.length || runs[0].status !== "completed" || runs[0].conclusion !== "success") throw new Error(`Latest ${workflow} result for ${commit} has not passed.`);
}
for (let page = 1; ; page++) {
  const alerts = api(`code-scanning/alerts?state=open&per_page=100&page=${page}`);
  if (alerts.some((alert) => ["critical", "high"].includes(alert.rule.security_severity_level) && alert.most_recent_instance?.commit_sha === commit)) throw new Error("Current CodeQL has unresolved high or critical findings.");
  if (alerts.length < 100) break;
}
process.stdout.write(`Signed tag and remote assurance verified for ${tag} at ${commit}.\n`);
