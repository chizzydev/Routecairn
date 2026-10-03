export async function analyze(_input, sdk) {
  const reply = await sdk.request({ url: "/", method: "HEAD", purpose: "Read explicit framework metadata" });
  const observations = [];
  if (reply.outcome === "TRANSMITTED" && reply.statusCode && !reply.errorCode) {
    const hint = reply.headers["x-powered-by"];
    if (typeof hint === "string") observations.push({ kind: "framework-hint", summary: "The response supplies a framework hint; it is not version proof", data: { value: hint.slice(0, 100), status: reply.statusCode } });
  }
  return { observations, findings: [], notes: observations.length ? [] : ["No explicit framework hint was observed."] };
}
