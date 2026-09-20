import type { HttpMethod } from "../../core/http/HttpTypes.js";

export const turnkeyAuthProviders = ["AUTH0", "COGNITO", "CLERK", "FIREBASE", "SUPABASE_AUTH"] as const;
export type TurnkeyAuthProvider = (typeof turnkeyAuthProviders)[number];

export const turnkeyAuthOperations = [
  "SIGN_UP", "SIGN_IN_PASSWORD", "REFRESH_TOKEN", "SIGN_OUT", "SEND_OTP", "VERIFY_OTP",
  "INVITE", "DELETE_USER", "OAUTH_AUTHORIZE", "OAUTH_TOKEN", "MFA_ENROLL", "MFA_CHALLENGE", "MFA_VERIFY"
] as const;
export type TurnkeyAuthOperation = (typeof turnkeyAuthOperations)[number];

export interface TurnkeyAuthAdapterConfig {
  id: string;
  provider: TurnkeyAuthProvider;
  baseUrl: string;
  tokenBaseUrl?: string | undefined;
  cognitoMode?: "HOSTED_UI" | "USER_POOLS_API" | undefined;
  clientIdSecretRef?: string | undefined;
  clientSecretRef?: string | undefined;
  apiKeySecretRef?: string | undefined;
  serviceKeySecretRef?: string | undefined;
  managementTokenSecretRef?: string | undefined;
}

export interface TurnkeyAuthRequestTemplate {
  method: HttpMethod;
  url: string;
  headers: Readonly<Record<string, string>>;
  bodyFormat?: "JSON" | "FORM";
  fields?: Readonly<Record<string, unknown>>;
  stateChanging: boolean;
  suggestedCaptures: Readonly<Record<string, string>>;
}

/** Resolves documented provider endpoints while leaving all credential values as worker-only references. */
export function resolveTurnkeyAuthRequest(config: TurnkeyAuthAdapterConfig, operation: TurnkeyAuthOperation, fields: Readonly<Record<string, unknown>> = {}): TurnkeyAuthRequestTemplate {
  const base = normalizedBase(config.baseUrl);
  const secret = (name: keyof Pick<TurnkeyAuthAdapterConfig, "clientIdSecretRef" | "clientSecretRef" | "apiKeySecretRef" | "serviceKeySecretRef" | "managementTokenSecretRef">): string => {
    const ref = config[name];
    if (!ref) throw new Error(`AUTH_PROVIDER_SECRET_REF_REQUIRED:${String(name)}`);
    return `{{SECRET:${ref}}}`;
  };
  const json = (method: HttpMethod, path: string, requestFields = fields, headers: Record<string, string> = {}, captures: Record<string, string> = {}): TurnkeyAuthRequestTemplate => ({ method, url: `${base}${path}`, headers, bodyFormat: "JSON", fields: requestFields, stateChanging: !["OAUTH_AUTHORIZE"].includes(operation), suggestedCaptures: captures });
  const form = (method: HttpMethod, path: string, requestFields = fields, headers: Record<string, string> = {}, captures: Record<string, string> = {}): TurnkeyAuthRequestTemplate => ({ method, url: `${base}${path}`, headers, bodyFormat: "FORM", fields: requestFields, stateChanging: operation !== "OAUTH_AUTHORIZE", suggestedCaptures: captures });
  const get = (path: string, queryFields = fields, headers: Record<string, string> = {}, stateChanging = false): TurnkeyAuthRequestTemplate => ({ method: "GET", url: `${base}${path}${queryString(queryFields)}`, headers, stateChanging, suggestedCaptures: {} });

  if (config.provider === "AUTH0") {
    const oauth = operation === "OAUTH_AUTHORIZE" ? get("/authorize") : operation === "OAUTH_TOKEN" || operation === "SIGN_IN_PASSWORD" || operation === "REFRESH_TOKEN" ? form("POST", "/oauth/token", fields, {}, { access_token: "access_token", refresh_token: "refresh_token", id_token: "id_token" }) : undefined;
    if (oauth) return oauth;
    const management = { Authorization: `Bearer ${secret("managementTokenSecretRef")}` };
    if (operation === "SIGN_UP") return json("POST", "/dbconnections/signup", fields, {}, { user_id: "_id" });
    if (operation === "SIGN_OUT") return get("/v2/logout", fields, {}, true);
    if (operation === "SEND_OTP") return json("POST", "/passwordless/start", fields);
    if (operation === "INVITE") return json("POST", "/api/v2/organizations/invitations", fields, management, { invitation_id: "id" });
    if (operation === "DELETE_USER") return json("DELETE", `/api/v2/users/${captureField(fields, "userId")}`, {}, management);
    if (operation === "MFA_ENROLL") return json("POST", "/mfa/associate", fields, {}, { recovery_codes: "recovery_codes", authenticator_secret: "secret" });
    if (operation === "MFA_CHALLENGE") return json("POST", "/mfa/challenge", fields, {}, { challenge_id: "challenge_id" });
    if (operation === "MFA_VERIFY" || operation === "VERIFY_OTP") return form("POST", "/oauth/token", fields, {}, { access_token: "access_token" });
  }

  if (config.provider === "COGNITO") {
    if (config.cognitoMode === "USER_POOLS_API") {
      const targets: Partial<Record<TurnkeyAuthOperation, string>> = { SIGN_UP: "SignUp", SIGN_IN_PASSWORD: "InitiateAuth", REFRESH_TOKEN: "InitiateAuth", SIGN_OUT: "GlobalSignOut", SEND_OTP: "ForgotPassword", VERIFY_OTP: "ConfirmForgotPassword", DELETE_USER: "DeleteUser", MFA_ENROLL: "AssociateSoftwareToken", MFA_CHALLENGE: "SetUserMFAPreference", MFA_VERIFY: "VerifySoftwareToken" };
      const target = targets[operation];
      if (!target) throw new Error(`AUTH_PROVIDER_OPERATION_REQUIRES_COGNITO_HOSTED_UI:${operation}`);
      const captures = operation === "SIGN_IN_PASSWORD" || operation === "REFRESH_TOKEN" ? { access_token: "AuthenticationResult.AccessToken", refresh_token: "AuthenticationResult.RefreshToken", id_token: "AuthenticationResult.IdToken" } : operation === "MFA_ENROLL" ? { totp_secret: "SecretCode", session: "Session" } : {};
      return json("POST", "", fields, { "Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": `AWSCognitoIdentityProviderService.${target}` }, captures);
    }
    if (operation === "OAUTH_AUTHORIZE") return get("/oauth2/authorize");
    if (["OAUTH_TOKEN", "SIGN_IN_PASSWORD", "REFRESH_TOKEN"].includes(operation)) return form("POST", "/oauth2/token", fields, {}, { access_token: "access_token", refresh_token: "refresh_token", id_token: "id_token" });
    if (operation === "SIGN_OUT") return get("/logout", fields, {}, true);
    throw new Error(`AUTH_PROVIDER_OPERATION_REQUIRES_COGNITO_USER_POOLS_API:${operation}`);
  }

  if (config.provider === "CLERK") {
    const headers = { Authorization: `Bearer ${secret("serviceKeySecretRef")}` };
    if (operation === "SIGN_UP") return json("POST", "/v1/users", fields, headers, { user_id: "id" });
    if (operation === "SIGN_IN_PASSWORD") return json("POST", "/v1/sessions", fields, headers, { session_id: "id" });
    if (operation === "SIGN_OUT") return json("POST", `/v1/sessions/${captureField(fields, "sessionId")}/revoke`, {}, headers);
    if (operation === "INVITE") return json("POST", "/v1/invitations", fields, headers, { invitation_id: "id" });
    if (operation === "DELETE_USER") return json("DELETE", `/v1/users/${captureField(fields, "userId")}`, {}, headers);
  }

  if (config.provider === "FIREBASE") {
    const key = secret("apiKeySecretRef");
    const path = (name: string) => `/v1/accounts:${name}?key=${key}`;
    if (operation === "SIGN_UP") return json("POST", path("signUp"), fields, {}, { user_id: "localId", id_token: "idToken", refresh_token: "refreshToken" });
    if (operation === "SIGN_IN_PASSWORD") return json("POST", path("signInWithPassword"), fields, {}, { user_id: "localId", id_token: "idToken", refresh_token: "refreshToken" });
    if (operation === "SEND_OTP") return json("POST", path("sendOobCode"), fields);
    if (operation === "VERIFY_OTP") return json("POST", path("update"), fields, {}, { id_token: "idToken" });
    if (operation === "DELETE_USER") return json("POST", path("delete"), fields);
    if (operation === "REFRESH_TOKEN") {
      const tokenBase = normalizedBase(config.tokenBaseUrl ?? (new URL(base).hostname === "identitytoolkit.googleapis.com" ? "https://securetoken.googleapis.com" : base));
      return { ...form("POST", `/v1/token?key=${key}`, fields, {}, { access_token: "access_token", refresh_token: "refresh_token", id_token: "id_token" }), url: `${tokenBase}/v1/token?key=${key}` };
    }
  }

  if (config.provider === "SUPABASE_AUTH") {
    const apiKey = secret("apiKeySecretRef");
    const headers: Record<string, string> = { apikey: apiKey };
    if (config.serviceKeySecretRef) headers.Authorization = `Bearer ${secret("serviceKeySecretRef")}`;
    if (operation === "SIGN_UP") return json("POST", "/auth/v1/signup", fields, headers, { user_id: "user.id", access_token: "access_token", refresh_token: "refresh_token" });
    if (operation === "SIGN_IN_PASSWORD") return json("POST", "/auth/v1/token?grant_type=password", fields, headers, { user_id: "user.id", access_token: "access_token", refresh_token: "refresh_token" });
    if (operation === "REFRESH_TOKEN") return json("POST", "/auth/v1/token?grant_type=refresh_token", fields, headers, { access_token: "access_token", refresh_token: "refresh_token" });
    if (operation === "SIGN_OUT") return json("POST", "/auth/v1/logout", fields, headers);
    if (operation === "SEND_OTP") return json("POST", "/auth/v1/otp", fields, headers);
    if (operation === "VERIFY_OTP") return json("POST", "/auth/v1/verify", fields, headers, { access_token: "access_token", refresh_token: "refresh_token" });
    if (operation === "INVITE") return json("POST", "/auth/v1/invite", fields, headers, { user_id: "id" });
    if (operation === "DELETE_USER") return json("DELETE", `/auth/v1/admin/users/${captureField(fields, "userId")}`, {}, headers);
    if (operation === "MFA_ENROLL") return json("POST", "/auth/v1/factors", fields, headers, { factor_id: "id", totp_secret: "totp.secret", qr_code: "totp.qr_code" });
    if (operation === "MFA_CHALLENGE") return json("POST", `/auth/v1/factors/${captureField(fields, "factorId")}/challenge`, fields, headers, { challenge_id: "id" });
    if (operation === "MFA_VERIFY") return json("POST", `/auth/v1/factors/${captureField(fields, "factorId")}/verify`, fields, headers, { access_token: "access_token", refresh_token: "refresh_token" });
    if (operation === "OAUTH_AUTHORIZE") return get("/auth/v1/authorize", fields, headers);
    if (operation === "OAUTH_TOKEN") return json("POST", "/auth/v1/token?grant_type=pkce", fields, headers, { access_token: "access_token", refresh_token: "refresh_token" });
  }

  throw new Error(`AUTH_PROVIDER_OPERATION_UNSUPPORTED:${config.provider}:${operation}`);
}

function normalizedBase(value: string): string {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || !["https:", "http:"].includes(url.protocol)) throw new Error("AUTH_PROVIDER_BASE_URL_INVALID");
  if (url.protocol === "http:" && !["127.0.0.1", "localhost", "::1", "[::1]"].includes(url.hostname)) throw new Error("AUTH_PROVIDER_HTTPS_REQUIRED");
  return url.toString().replace(/\/$/, "");
}

function captureField(fields: Readonly<Record<string, unknown>>, name: string): string {
  const value = fields[name];
  if (typeof value !== "string" || !/^\{\{CAPTURE:[A-Za-z0-9._-]+\}\}$/.test(value)) throw new Error(`AUTH_PROVIDER_CAPTURE_REQUIRED:${name}`);
  return value;
}

function queryString(fields: Readonly<Record<string, unknown>>): string {
  const entries = Object.entries(fields);
  if (!entries.length) return "";
  return `?${entries.map(([key, value]) => `${encodeURIComponent(key)}=${encodeTemplateValue(value)}`).join("&")}`;
}

function encodeTemplateValue(value: unknown): string {
  if (!["string", "number", "boolean"].includes(typeof value)) throw new Error("AUTH_PROVIDER_QUERY_FIELD_INVALID");
  return encodeURIComponent(String(value)).replace(/%7B%7B(SECRET|CAPTURE)%3A([A-Za-z0-9._-]+)%7D%7D/gi, "{{$1:$2}}");
}
