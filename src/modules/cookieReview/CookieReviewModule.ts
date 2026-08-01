import type { Finding } from "../../core/findings/Finding.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { cookieFindings } from "./CookieRules.js";

export class CookieReviewModule implements RouteCairnPlugin {
  public readonly name = "cookie-review";
  public readonly description = "Reviews Set-Cookie attributes and scores issues based on cookie sensitivity.";
  public readonly phase = "analysis";

  public async run(context: ScanContext): Promise<ModuleResult> {
    const rawFindings = context.state.getResponses().flatMap((response) => cookieFindings(response));
    const findings = groupCookieFindings(rawFindings);

    return {
      pluginName: this.name,
      findings,
      notes: [`Cookie findings: ${findings.length} grouped from ${rawFindings.length} observations.`]
    };
  }
}

function groupCookieFindings(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();

  for (const finding of findings) {
    const host = safeHost(finding.url);
    const cookieName = finding.evidence.source?.split(":")[0]?.trim().toLowerCase() ?? "unknown-cookie";
    const key = `${host}:${finding.title}:${cookieName}`;
    const group = groups.get(key) ?? [];
    group.push(finding);
    groups.set(key, group);
  }

  return [...groups.values()].map((group) => summarizeCookieGroup(group));
}

function summarizeCookieGroup(group: Finding[]): Finding {
  const first = group[0]!;
  const urls = [...new Set(group.map((finding) => finding.url))];
  const origin = safeOrigin(first.url);
  const sampleUrls = urls.slice(0, 5).join(", ");

  return {
    ...first,
    url: origin,
    evidence: {
      ...first.evidence,
      url: origin,
      source: `${first.evidence.source} Observed on ${urls.length} response(s). Sample URLs: ${sampleUrls}.`
    },
    manualTestingSuggestions: [
      "Verify the cookie purpose and whether the missing attribute is intentional for this cookie type.",
      "Review one representative response rather than every repeated URL."
    ]
  };
}

function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function safeOrigin(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}
