export async function analyze(_input, sdk) {
  const reply = await sdk.request({ url: "/graphql?query=%7B__typename%7D", method: "GET", purpose: "Recognize a read-only GraphQL response envelope" });
  const observations = [];
  if (reply.statusCode === 200 && !reply.errorCode && !reply.truncated && reply.bodyPreview) {
    try { const envelope = JSON.parse(reply.bodyPreview); if (envelope.data && typeof envelope.data.__typename === "string") observations.push({ kind: "graphql-envelope", summary: "The approved route returned a GraphQL query root name", data: { rootType: envelope.data.__typename.slice(0, 100) } }); } catch { /* Invalid or redacted responses remain inconclusive. */ }
  }
  return { observations, findings: [], notes: observations.length ? [] : ["A complete GraphQL response was not observed."] };
}
