export async function analyze(_input, sdk) {
  const reply = await sdk.request({ url: "/", method: "HEAD", purpose: "Review browser response hardening headers" });
  if (reply.outcome !== "TRANSMITTED" || !reply.statusCode || reply.errorCode) return { observations: [], findings: [], notes: ["Header check was inconclusive; inspect the capability summary."] };
  const headers = reply.headers;
  const missing = ["content-security-policy", "x-content-type-options"].filter((name) => !headers[name]);
  return { observations: [{ kind: "response-headers", summary: "Inspected bounded response metadata", data: { status: reply.statusCode, missingCount: missing.length } }], findings: missing.length ? [{ title: "Browser hardening headers absent", category: "Configuration", severity: "Info", confidence: "High", endpoint: "/", description: `The response lacks ${missing.join(", ")}. Review whether this route serves browser content before increasing severity.`, remediation: "Apply an appropriate CSP and X-Content-Type-Options where browser content is served." }] : [], notes: [] };
}
