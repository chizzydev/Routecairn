import { createServer } from "node:http";
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import Provider from "oidc-provider";

/** Real independently maintained OIDC protocol implementation, with disposable
 * loopback users and a deliberate secure/vulnerable application comparison. */
export async function createActiveOidcLab() {
  const sessions = new Map(); const completed = new Map(); let provider;
  const sendJson = (res, status, value) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(value)); };
  const rp = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, applicationOrigin); const parts = url.pathname.split("/"); const technique = parts[2]; const unsafe = parts[1] === "vulnerable";
      if (parts[3] === "cleanup") { const canary = url.searchParams.get("routecairn_canary"); for (const [id, session] of sessions) if (session.canary === canary) { sessions.delete(id); completed.delete(id); } sendJson(res, 200, { removed: true }); return; }
      const id = /(?:^|;\s*)rca_oidc=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
      if (parts[3] === "identity") { const identity = completed.get(id); const linking = technique === "OAUTH_ACCOUNT_LINK" && req.headers["x-routecairn-lab-rp"] === "a"; sendJson(res, identity || linking ? 200 : 401, { account: linking ? "lab-account-a" : identity ?? null, linkedAccount: linking ? identity ?? null : null }); return; }
      const callbackUrl = `${applicationOrigin}/${parts[1]}/${technique}/callback`;
      if (parts[3] === "start") {
        const id = randomBytes(20).toString("hex"); const state = randomBytes(24).toString("base64url"); const nonce = randomBytes(24).toString("base64url"); const verifier = randomBytes(32).toString("base64url");
        sessions.set(id, { state, nonce, verifier, canary: url.searchParams.get("routecairn_canary") });
        const authorize = new URL(`${issuer}/auth`); authorize.search = new URLSearchParams({ response_type: "code", client_id: "routecairn-lab", scope: "openid", redirect_uri: callbackUrl, state, nonce, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" }).toString();
        res.writeHead(302, { location: authorize.toString(), "set-cookie": `rca_oidc=${id}; HttpOnly; Path=/; SameSite=Lax` }); res.end(); return;
      }
      if (parts[3] !== "callback" || !sessions.has(id)) { sendJson(res, 400, {}); return; }
      const session = sessions.get(id);
      if (!unsafe && (url.searchParams.get("state") !== session.state || url.searchParams.get("iss") !== issuer || url.searchParams.has("provider"))) { sendJson(res, 400, {}); return; }
      const response = await fetch(`${issuer}/token`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", client_id: "routecairn-lab", code: url.searchParams.get("code") ?? "", redirect_uri: callbackUrl, code_verifier: session.verifier }), signal: AbortSignal.timeout(5000) });
      if (!response.ok) { sendJson(res, 400, {}); return; }
      const token = (await response.json()).id_token; const [header, payload, signature] = token.split("."); const claims = JSON.parse(Buffer.from(payload, "base64url"));
      if (JSON.parse(Buffer.from(header, "base64url")).alg !== "RS256" || !verify("RSA-SHA256", Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature, "base64url")) || claims.iss !== issuer || claims.aud !== "routecairn-lab" || claims.nonce !== session.nonce || claims.exp <= Date.now() / 1000) { sendJson(res, 400, {}); return; }
      if (!unsafe && technique === "OAUTH_ACCOUNT_LINK" && claims.sub !== "lab-account-a") { sendJson(res, 403, {}); return; }
      completed.set(id, claims.sub); sendJson(res, 200, { complete: true });
    } catch { sendJson(res, 500, { error: "LAB_PROTOCOL_FAILURE" }); }
  });
  await new Promise((done) => rp.listen(0, "127.0.0.1", done)); const applicationOrigin = `http://127.0.0.1:${rp.address().port}`;
  const as = createServer(async (req, res) => {
    try {
      if (req.url.startsWith("/interaction/")) {
        const details = await provider.interactionDetails(req, res); const accountId = req.headers["x-routecairn-lab-account"] === "b" ? "lab-account-b" : "lab-account-a";
        const grant = new provider.Grant({ accountId, clientId: details.params.client_id }); grant.addOIDCScope("openid");
        await provider.interactionFinished(req, res, { login: { accountId }, consent: { grantId: await grant.save() } }, { mergeWithLastSubmission: false }); return;
      }
      provider.callback()(req, res);
    } catch { sendJson(res, 500, { error: "LAB_AUTH_SERVER_FAILURE" }); }
  });
  await new Promise((done) => as.listen(0, "127.0.0.1", done)); const issuer = `http://127.0.0.1:${as.address().port}`;
  const keys = generateKeyPairSync("rsa", { modulusLength: 2048 }); const publicKey = createPublicKey(keys.privateKey); const jwk = keys.privateKey.export({ format: "jwk" });
  jwk.kid = "ephemeral-lab"; jwk.use = "sig"; jwk.alg = "RS256";
  const techniques = ["OAUTH_STATE", "OAUTH_ISSUER", "OAUTH_MIX_UP", "OAUTH_ACCOUNT_LINK"];
  provider = new Provider(issuer, { clients: [{ client_id: "routecairn-lab", token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"], redirect_uris: ["secure", "vulnerable"].flatMap((mode) => techniques.map((technique) => `${applicationOrigin}/${mode}/${technique}/callback`)) }], jwks: { keys: [jwk] }, cookies: { keys: [randomBytes(32).toString("hex")] }, features: { devInteractions: { enabled: false } }, pkce: { required: () => true }, findAccount: async (_ctx, sub) => ({ accountId: sub, claims: async () => ({ sub }) }) });
  return { issuer, applicationOrigin, activeSessions: () => sessions.size, cleanup: async (canary) => { for (const [id, session] of sessions) if (session.canary === canary) { sessions.delete(id); completed.delete(id); } }, close: async () => { sessions.clear(); completed.clear(); as.closeAllConnections(); rp.closeAllConnections(); await Promise.all([new Promise((done) => as.close(done)), new Promise((done) => rp.close(done))]); } };
}
