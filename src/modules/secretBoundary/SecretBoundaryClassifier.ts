import type { SecretBoundarySurface, SecretClassification } from "./SecretBoundaryTypes.js";

export interface SecretClassificationInput {
  name: string;
  value: string;
  surface: SecretBoundarySurface;
  publicExposure: boolean;
  cookie?: { httpOnly: boolean; secure: boolean; sameSite?: string };
}

const clientSafeName = /^(?:NEXT_PUBLIC_|VITE_|PUBLIC_)|(?:SUPABASE_ANON_KEY|SUPABASE_PUBLISHABLE_KEY|STRIPE_PUBLISHABLE_KEY|SENTRY_DSN|FIREBASE_API_KEY)/i;
const serverName = /(?:SERVICE[_-]?ROLE|ADMIN[_-]?(?:KEY|TOKEN)|MASTER[_-]?(?:KEY|TOKEN)|ROOT[_-]?(?:KEY|TOKEN)|CLIENT[_-]?SECRET|API[_-]?SECRET|SIGNING[_-]?SECRET|WEBHOOK[_-]?SECRET|JWT[_-]?SECRET|SESSION[_-]?SECRET|ENCRYPTION[_-]?KEY|DATABASE_URL|DB_PASSWORD|PRIVATE[_-]?KEY|SECRET[_-]?KEY)/i;
const sessionName = /(?:ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|ID[_-]?TOKEN|SESSION|AUTH[_-]?TOKEN|BEARER|JWT|SID)(?:$|[_-])/i;
const oneTimeName = /(?:RESET|RECOVERY|VERIFY|VERIFICATION|INVITE|MAGIC[_-]?LINK|OTP|ONE[_-]?TIME).*(?:TOKEN|CODE)|(?:TOKEN|CODE).*(?:RESET|RECOVERY|VERIFY|INVITE|OTP)/i;
const personalHighName = /(?:PASSWORD(?:[_-]?HASH)?|SSN|SOCIAL[_-]?SECURITY|TAX[_-]?ID|NATIONAL[_-]?ID|PASSPORT|CARD[_-]?NUMBER|PAN|CVV|CVC|BANK[_-]?ACCOUNT|ROUTING[_-]?NUMBER|IBAN|PRIVATE[_-]?(?:EMAIL|PHONE|ADDRESS))/i;
const personalReviewName = /(?:EMAIL|PHONE|ADDRESS|DATE_OF_BIRTH|DOB)/i;
const metadataName = /(?:BUILD_ID|BUILD_NUMBER|COMMIT_SHA|GIT_SHA|RELEASE|VERSION|SOURCE_ROOT|DEPLOYMENT_ID)/i;

export function classifyTransientSecret(input: SecretClassificationInput): SecretClassification {
  const name = input.name.trim();
  const value = input.value.trim();
  const clientNamed = clientSafeName.test(name);
  const jwt = decodeJwt(value);
  const supabaseRole = supabaseJwtRole(jwt);

  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(value)) return result("PRIVATE_KEY", "SERVER_ONLY", "CRITICAL", "CONFIRMED_SENSITIVE_EXPOSURE", "CONFIRMED", "PRIVATE_KEY_MATERIAL", true, clientNamed, "PEM");
  if (/^sb_secret_[A-Za-z0-9_-]{12,}$/.test(value) || supabaseRole === "service_role" || /SUPABASE_SERVICE_ROLE/i.test(name)) return result("SUPABASE_SERVICE_ROLE_KEY", "SERVER_ONLY", "CRITICAL", "CONFIRMED_SENSITIVE_EXPOSURE", "CONFIRMED", "SUPABASE_SERVICE_ROLE_SEMANTICS", true, clientNamed, /^sb_secret_/.test(value) ? "SUPABASE_SECRET" : "JWT", supabaseRole);
  if (/^(?:sk_(?:live|test)_|rk_(?:live|test)_)[A-Za-z0-9]{8,}$/.test(value) || /(?:STRIPE|PAYPAL|ADYEN|BRAINTREE|PADDLE).*(?:SECRET|PRIVATE|ACCESS_TOKEN)/i.test(name)) return result("PAYMENT_PROVIDER_SECRET", "SERVER_ONLY", /_live_/.test(value) ? "CRITICAL" : "HIGH", "CONFIRMED_SENSITIVE_EXPOSURE", "CONFIRMED", "PAYMENT_SECRET_SEMANTICS", true, clientNamed, "PAYMENT_SECRET");
  if (/^(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})$/.test(value) || /^(?:xox[baprs]-|AIza)[A-Za-z0-9_-]{16,}$/.test(value) && serverName.test(name)) return result("SERVER_CREDENTIAL", "SERVER_ONLY", "CRITICAL", "CONFIRMED_SENSITIVE_EXPOSURE", "CONFIRMED", "KNOWN_SERVER_CREDENTIAL_FORMAT", true, clientNamed, "VENDOR_CREDENTIAL");
  if (/^(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis):\/\//i.test(value) && /:\/\/[^:/\s]+:[^@/\s]+@/.test(value)) return result("DATABASE_CREDENTIAL", "SERVER_ONLY", "CRITICAL", "CONFIRMED_SENSITIVE_EXPOSURE", "CONFIRMED", "DATABASE_URL_WITH_CREDENTIALS", true, clientNamed, "CONNECTION_URL");
  if (serverName.test(name) && value.length >= 8 && !placeholder(value)) return result("SERVER_CREDENTIAL", "SERVER_ONLY", "HIGH", "CONFIRMED_SENSITIVE_EXPOSURE", "HIGH", "SERVER_ONLY_NAME_AND_VALUE", true, clientNamed, jwt ? "JWT" : "OPAQUE");
  if (oneTimeName.test(name) && value.length >= 6 && !placeholder(value)) {
    const storage = userSecretStorage(input);
    return result("ONE_TIME_OR_RECOVERY_TOKEN", "USER_SECRET", storage?.impact ?? "HIGH", storage?.outcome ?? "CONFIRMED_SENSITIVE_EXPOSURE", "HIGH", storage?.reasonCode ?? "ONE_TIME_TOKEN_NAME", storage?.findingEligible ?? true, clientNamed, jwt ? "JWT" : "OPAQUE");
  }

  const sessionSemantic = (sessionName.test(`${name}_`) && value.length >= 8) || Boolean(jwt && (typeof jwt.sub === "string" || typeof jwt.session_id === "string") && supabaseRole !== "anon");
  if (sessionSemantic && !placeholder(value)) {
    const storage = userSecretStorage(input);
    return result("USER_SESSION_SECRET", "USER_SECRET", storage?.impact ?? "CRITICAL", storage?.outcome ?? "CONFIRMED_SENSITIVE_EXPOSURE", "HIGH", storage?.reasonCode ?? "SESSION_MATERIAL_IN_RESPONSE", storage?.findingEligible ?? true, clientNamed, jwt ? "JWT" : "OPAQUE", supabaseRole);
  }

  if (/^sb_publishable_[A-Za-z0-9_-]{8,}$/.test(value)) return result("SUPABASE_PUBLISHABLE_KEY", "CLIENT_SAFE", "NONE", "EXPECTED_PUBLIC_CLIENT_MATERIAL", "CONFIRMED", "SUPABASE_PUBLISHABLE_FORMAT", false, false, "SUPABASE_PUBLISHABLE");
  if (supabaseRole === "anon" || /SUPABASE_ANON_KEY/i.test(name)) return result("SUPABASE_ANON_KEY", "CLIENT_SAFE", "NONE", "EXPECTED_PUBLIC_CLIENT_MATERIAL", supabaseRole === "anon" ? "CONFIRMED" : "MEDIUM", supabaseRole === "anon" ? "SUPABASE_ANON_JWT_CLAIM" : "SUPABASE_ANON_NAME", false, false, jwt ? "JWT" : "OPAQUE", supabaseRole);
  if (/^(?:pk_(?:live|test)_|pub_)[A-Za-z0-9_-]{8,}$/.test(value) || /^AIza[A-Za-z0-9_-]{20,}$/.test(value) || /^https:\/\/[A-Za-z0-9.-]+\/[0-9]+:[A-Za-z0-9]+@/.test(value)) return result("PUBLISHABLE_CLIENT_KEY", "CLIENT_SAFE", "NONE", "EXPECTED_PUBLIC_CLIENT_MATERIAL", "HIGH", "KNOWN_PUBLISHABLE_CLIENT_FORMAT", false, false, "PUBLISHABLE_KEY");
  if (clientNamed) return result("PUBLIC_CLIENT_CONFIG", "CLIENT_SAFE", "NONE", "EXPECTED_PUBLIC_CLIENT_MATERIAL", "HIGH", "EXPLICIT_CLIENT_SAFE_NAME", false, false, looksLikeUrl(value) ? "URL" : "CONFIG");

  if (personalHighName.test(name) && value.length > 0 && !placeholder(value)) return result("PERSONAL_DATA", "PERSONAL_DATA", input.publicExposure ? "HIGH" : "MEDIUM", input.publicExposure ? "SENSITIVE_FIELD_EXPOSURE" : "NEEDS_REVIEW", "HIGH", "HIGH_SENSITIVITY_FIELD_NAME", input.publicExposure, false, "FIELD_VALUE");
  if (personalReviewName.test(name) && value.length > 0 && !placeholder(value)) return result("PERSONAL_DATA", "PERSONAL_DATA", input.publicExposure ? "MEDIUM" : "LOW", "NEEDS_REVIEW", "MEDIUM", "PERSONAL_DATA_FIELD_NAME", false, false, "FIELD_VALUE");
  if (metadataName.test(name)) return result("INTERNAL_METADATA", "INTERNAL", "INFORMATIONAL", "METADATA_EXPOSURE", "HIGH", "BUILD_OR_RELEASE_METADATA", false, false, "METADATA");
  if (/(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|API[_-]?KEY|AUTH)/i.test(name) && value.length >= 8 && !placeholder(value)) return result("UNKNOWN_SECRET_LIKE", "UNKNOWN", "MEDIUM", "NEEDS_REVIEW", "MEDIUM", "GENERIC_SECRET_LIKE_NAME", false, clientNamed, jwt ? "JWT" : "OPAQUE", supabaseRole);
  return result("NON_SENSITIVE", "NONE", "NONE", "NOT_SENSITIVE", "HIGH", "NO_SENSITIVE_SEMANTICS", false, false, looksLikeUrl(value) ? "URL" : "PLAIN");
}

function userSecretStorage(input: SecretClassificationInput): Pick<SecretClassification, "impact" | "outcome" | "reasonCode" | "findingEligible"> | undefined {
  if (input.surface === "COOKIE" && input.cookie?.httpOnly && input.cookie.secure) {
    return { impact: "NONE", outcome: "SECURE_COOKIE_STORAGE", reasonCode: "SECURE_HTTPONLY_SESSION_COOKIE", findingEligible: false };
  }
  if (input.surface === "COOKIE" && input.cookie?.httpOnly) {
    return { impact: "MEDIUM", outcome: "COOKIE_TRANSPORT_RISK", reasonCode: "HTTPONLY_COOKIE_WITHOUT_SECURE", findingEligible: true };
  }
  if (["COOKIE", "BROWSER_LOCAL_STORAGE", "BROWSER_SESSION_STORAGE"].includes(input.surface)) {
    return { impact: "HIGH", outcome: "CLIENT_STORAGE_RISK", reasonCode: "SCRIPT_ACCESSIBLE_SESSION_MATERIAL", findingEligible: true };
  }
  return undefined;
}

function result(materialClass: SecretClassification["materialClass"], boundary: SecretClassification["boundary"], impact: SecretClassification["impact"], outcome: SecretClassification["outcome"], confidence: SecretClassification["confidence"], reasonCode: string, findingEligible: boolean, clientSafeNameConflict: boolean, tokenFormat: string, supabaseRole?: SecretClassification["supabaseRole"]): SecretClassification {
  return { materialClass, boundary, impact, outcome, confidence, reasonCode, findingEligible, clientSafeNameConflict, tokenFormat, ...(supabaseRole ? { supabaseRole } : {}) };
}

function decodeJwt(value: string): Record<string, unknown> | undefined {
  const parts = value.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0 || part.length > 8192)) return undefined;
  try {
    const decoded = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
    return decoded && typeof decoded === "object" && !Array.isArray(decoded) ? decoded as Record<string, unknown> : undefined;
  } catch { return undefined; }
}

function supabaseJwtRole(jwt: Record<string, unknown> | undefined): SecretClassification["supabaseRole"] | undefined {
  if (!jwt) return undefined;
  const role = jwt.role;
  if (role === "anon" || role === "authenticated" || role === "service_role") return role;
  return typeof role === "string" ? "other" : undefined;
}

function placeholder(value: string): boolean { return /^(?:example|sample|placeholder|changeme|replace[_-]?me|your[_-].*|xxx+|test|undefined|null)$/i.test(value) || /^<[^>]+>$/.test(value); }
function looksLikeUrl(value: string): boolean { try { const url = new URL(value); return url.protocol === "http:" || url.protocol === "https:"; } catch { return false; } }
