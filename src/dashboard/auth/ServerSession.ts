import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { clamp, nowIso } from "../db/DashboardDatabase.js";
import { hashPassword, needsPasswordRehash, validatePasswordPolicy, verifyPassword } from "./PasswordHashing.js";
import { hasPermission, permissionsForRole, type DashboardPermission, type DashboardPrincipal, type DashboardRole } from "./Permissions.js";
import { SessionError } from "./LocalSession.js";

export interface ServerRuntimeSecurity {
  publicOrigin: string;
  sessionSecret: string;
  trustProxy: boolean;
  developmentInsecureHttp: boolean;
}

export interface DashboardUserSummary {
  id: string;
  login: string;
  role: DashboardRole;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
  activeSessionCount: number;
}

const sessionTtlMs = 12 * 60 * 60 * 1000;
const idleTtlMs = 2 * 60 * 60 * 1000;
const loginWindowMs = 10 * 60 * 1000;
const maxFailuresPerLogin = 8;
const maxFailuresPerSource = 40;
const cooldownMs = 5 * 60 * 1000;
const maxRetainedAttempts = 1000;

export class ServerSessionManager {
  public constructor(private readonly database: DashboardDatabase, private readonly security: ServerRuntimeSecurity) {}

  public hasEnabledOwner(): boolean {
    return Boolean(this.database.db.prepare("SELECT id FROM dashboard_users WHERE role = 'OWNER' AND enabled = 1 LIMIT 1").get());
  }

  public async createFirstOwner(login: string, password: string): Promise<string> {
    if (this.database.db.prepare("SELECT id FROM dashboard_users WHERE role = 'OWNER' LIMIT 1").get()) {
      throw new Error("First owner already exists.");
    }
    const id = await this.createUser({ login, password, role: "OWNER", createdByUserId: undefined });
    this.audit("SYSTEM", "USER_CREATED", "USER", id, "First owner created.");
    return id;
  }

  public async createUser(input: { login: string; password: string; role: DashboardRole; createdByUserId?: string | undefined }): Promise<string> {
    const normalized = normalizeLogin(input.login);
    validatePasswordPolicy(input.password);
    const passwordHash = await hashPassword(input.password);
    const id = cryptoRandomId();
    const now = nowIso();
    this.database.transaction(() => {
      this.database.db
        .prepare(
          "INSERT INTO dashboard_users (id, login, normalized_login, password_hash, role, enabled, created_at, updated_at, password_changed_at, created_by_user_id) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)"
        )
        .run(id, clamp(input.login, 320), normalized, passwordHash, input.role, now, now, now, input.createdByUserId ?? null);
      const organization = this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key = 'default_organization_id'").get() as { value: string } | undefined;
      if (organization) this.database.db.prepare("INSERT INTO organization_memberships (organization_id,user_id,role,created_by,created_at,updated_at) VALUES (?, ?, ?, ?, ?, ?)").run(organization.value, id, input.role === "OWNER" ? "OWNER" : input.role, input.createdByUserId ?? "SYSTEM", now, now);
    });
    return id;
  }

  public listUsers(): DashboardUserSummary[] {
    const rows = this.database.db.prepare("SELECT * FROM dashboard_users ORDER BY created_at ASC LIMIT 500").all() as DbUserRow[];
    return rows.map((row) => userSummary(this.database, row));
  }

  public async resetPassword(userId: string, password: string): Promise<void> {
    const passwordHash = await hashPassword(password);
    const now = nowIso();
    this.database.transaction(() => {
      this.database.db.prepare("UPDATE dashboard_users SET password_hash = ?, password_changed_at = ?, updated_at = ?, failed_login_count = 0, locked_until = NULL WHERE id = ?").run(passwordHash, now, now, userId);
      this.revokeUserSessions(userId);
    });
  }

  public setEnabled(userId: string, enabled: boolean): void {
    this.database.transaction(() => {
      if (!enabled) this.assertNotFinalEnabledOwner(userId);
      this.database.db.prepare("UPDATE dashboard_users SET enabled = ?, updated_at = ? WHERE id = ?").run(enabled ? 1 : 0, nowIso(), userId);
      if (!enabled) this.revokeUserSessions(userId);
    });
  }

  public setRole(userId: string, role: DashboardRole): void {
    if (role !== "OWNER") this.assertNotFinalEnabledOwner(userId);
    this.database.db.prepare("UPDATE dashboard_users SET role = ?, updated_at = ? WHERE id = ?").run(role, nowIso(), userId);
  }

  public revokeUserSessions(userId: string): void {
    this.database.db.prepare("UPDATE dashboard_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ? AND revoked_at IS NULL").run(nowIso(), userId);
  }

  private assertNotFinalEnabledOwner(userId: string): void {
    const user = this.database.db.prepare("SELECT role, enabled FROM dashboard_users WHERE id = ?").get(userId) as { role: DashboardRole; enabled: number } | undefined;
    if (!user || user.role !== "OWNER" || user.enabled !== 1) return;
    const owners = this.database.db.prepare("SELECT COUNT(*) AS count FROM dashboard_users WHERE role = 'OWNER' AND enabled = 1").get() as { count: number };
    if (owners.count <= 1) throw new Error("FINAL_OWNER_REQUIRED: The final enabled owner cannot be disabled or demoted.");
  }

  public async login(input: { login: string; password: string; request: IncomingMessage; response: ServerResponse }): Promise<{ csrfToken: string; user: DashboardUserSummary; permissions: DashboardPermission[] }> {
    const normalized = normalizeLogin(input.login);
    const source = sourceFingerprint(input.request, this.security.sessionSecret);
    const loginFp = keyedHash(normalized, this.security.sessionSecret);
    this.enforceThrottle(loginFp, source);

    const generic = new SessionError("Invalid username or password.");
    const user = this.database.db.prepare("SELECT * FROM dashboard_users WHERE normalized_login = ?").get(normalized) as DbUserRow | undefined;
    if (!user || !user.enabled) {
      this.recordAttempt(loginFp, source, false, user ? "DISABLED" : "INVALID");
      throw generic;
    }

    const verified = await verifyPassword(user.password_hash, input.password);
    if (!verified) {
      this.recordAttempt(loginFp, source, false, "INVALID");
      this.database.db.prepare("UPDATE dashboard_users SET failed_login_count = failed_login_count + 1, locked_until = CASE WHEN failed_login_count + 1 >= ? THEN ? ELSE locked_until END WHERE id = ?").run(maxFailuresPerLogin, new Date(Date.now() + cooldownMs).toISOString(), user.id);
      throw generic;
    }

    if (user.locked_until && Date.parse(user.locked_until) > Date.now()) {
      this.recordAttempt(loginFp, source, false, "COOLDOWN");
      throw generic;
    }

    const sessionToken = token();
    const csrfToken = token();
    const sessionId = cryptoRandomId();
    const now = nowIso();
    const expiresAt = new Date(Date.now() + sessionTtlMs).toISOString();
    this.database.transaction(() => {
      this.database.db
        .prepare("INSERT INTO dashboard_sessions (id, user_id, token_hash, csrf_token_hash, created_at, last_seen_at, expires_at, safe_user_agent, safe_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(sessionId, user.id, tokenHash(sessionToken, this.security.sessionSecret), tokenHash(csrfToken, this.security.sessionSecret), now, now, expiresAt, safeHeader(input.request.headers["user-agent"]), source.slice(0, 24));
      this.database.db.prepare("INSERT INTO dashboard_csrf_tokens (session_id, token_hash, created_at) VALUES (?, ?, ?)").run(sessionId, tokenHash(csrfToken, this.security.sessionSecret), now);
      this.database.db.prepare("UPDATE dashboard_users SET last_login_at = ?, failed_login_count = 0, locked_until = NULL WHERE id = ?").run(now, user.id);
      this.recordAttempt(loginFp, source, true);
      if (needsPasswordRehash(user.password_hash)) {
        void hashPassword(input.password).then((rehash) => this.database.db.prepare("UPDATE dashboard_users SET password_hash = ? WHERE id = ?").run(rehash, user.id));
      }
    });
    input.response.setHeader("Set-Cookie", this.cookie(sessionToken, Date.now() + sessionTtlMs));
    const updated = this.database.db.prepare("SELECT * FROM dashboard_users WHERE id = ?").get(user.id) as DbUserRow;
    return { csrfToken, user: userSummary(this.database, updated), permissions: permissionsForRole(user.role) };
  }

  public loginFederated(userId: string, request: IncomingMessage, response: ServerResponse): { csrfToken: string; user: DashboardUserSummary; permissions: DashboardPermission[] } {
    const user = this.database.db.prepare("SELECT * FROM dashboard_users WHERE id=? AND enabled=1").get(userId) as DbUserRow | undefined;
    if (!user) throw new SessionError("Federated identity is not linked to an enabled dashboard user.");
    const sessionToken = token(); const csrfToken = token(); const sessionId = cryptoRandomId(); const now = nowIso(); const expiresAt = new Date(Date.now() + sessionTtlMs).toISOString();
    this.database.transaction(() => {
      this.database.db.prepare("INSERT INTO dashboard_sessions (id,user_id,token_hash,csrf_token_hash,created_at,last_seen_at,expires_at,safe_user_agent,safe_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(sessionId, user.id, tokenHash(sessionToken, this.security.sessionSecret), tokenHash(csrfToken, this.security.sessionSecret), now, now, expiresAt, safeHeader(request.headers["user-agent"]), sourceFingerprint(request, this.security.sessionSecret).slice(0, 24));
      this.database.db.prepare("INSERT INTO dashboard_csrf_tokens (session_id,token_hash,created_at) VALUES (?, ?, ?)").run(sessionId, tokenHash(csrfToken, this.security.sessionSecret), now);
      this.database.db.prepare("UPDATE dashboard_users SET last_login_at=? WHERE id=?").run(now, user.id);
    });
    response.setHeader("Set-Cookie", this.cookie(sessionToken, Date.now() + sessionTtlMs));
    return { csrfToken, user: userSummary(this.database, user), permissions: permissionsForRole(user.role) };
  }

  public requireSession(request: IncomingMessage): DashboardPrincipal {
    const rawToken = parseCookies(request.headers.cookie ?? "").get("routecairn_session");
    if (!rawToken) throw new SessionError("Dashboard session required.");
    const token = tokenHash(rawToken, this.security.sessionSecret);
    const row = this.database.db
      .prepare(
        `SELECT dashboard_sessions.*, dashboard_users.login, dashboard_users.role, dashboard_users.enabled
         FROM dashboard_sessions JOIN dashboard_users ON dashboard_users.id = dashboard_sessions.user_id
         WHERE dashboard_sessions.token_hash = ? AND dashboard_sessions.revoked_at IS NULL`
      )
      .get(token) as DbSessionJoinRow | undefined;
    if (!row || !row.enabled || Date.parse(row.expires_at) < Date.now() || Date.parse(row.last_seen_at) + idleTtlMs < Date.now()) {
      throw new SessionError("Dashboard session required.");
    }
    this.database.db.prepare("UPDATE dashboard_sessions SET last_seen_at = ? WHERE id = ?").run(nowIso(), row.id);
    return { mode: "server", userId: row.user_id, login: row.login, role: row.role, csrfToken: row.csrf_token_hash };
  }

  public requireMutation(request: IncomingMessage, csrfToken: string | undefined): DashboardPrincipal {
    const principal = this.requireSession(request);
    if (!isAllowedOrigin(request, this.security.publicOrigin, this.security.trustProxy)) throw new SessionError("Origin rejected.");
    const contentType = request.headers["content-type"] ?? "";
    if (!String(contentType).toLowerCase().startsWith("application/json")) throw new SessionError("JSON content type required.");
    const rawSessionToken = parseCookies(request.headers.cookie ?? "").get("routecairn_session");
    const candidate = csrfToken ? tokenHash(csrfToken, this.security.sessionSecret) : "";
    const accepted = rawSessionToken && csrfToken ? this.database.db.prepare(`SELECT 1 FROM dashboard_csrf_tokens JOIN dashboard_sessions ON dashboard_sessions.id = dashboard_csrf_tokens.session_id WHERE dashboard_sessions.token_hash = ? AND dashboard_sessions.revoked_at IS NULL AND dashboard_csrf_tokens.token_hash = ?`).get(tokenHash(rawSessionToken, this.security.sessionSecret), candidate) : undefined;
    if (!accepted) throw new SessionError("CSRF token rejected.");
    return principal;
  }

  public refreshCsrf(request: IncomingMessage): string {
    this.requireSession(request);
    if (!isAllowedOrigin(request, this.security.publicOrigin, this.security.trustProxy)) throw new SessionError("Origin rejected.");
    const contentType = request.headers["content-type"] ?? "";
    if (!String(contentType).toLowerCase().startsWith("application/json")) throw new SessionError("JSON content type required.");
    const rawSessionToken = parseCookies(request.headers.cookie ?? "").get("routecairn_session");
    if (!rawSessionToken) throw new SessionError("Dashboard session required.");
    const csrfToken = token();
    const session = this.database.db.prepare("SELECT id FROM dashboard_sessions WHERE token_hash = ? AND revoked_at IS NULL").get(tokenHash(rawSessionToken, this.security.sessionSecret)) as { id: string } | undefined;
    if (!session) throw new SessionError("Dashboard session required.");
    const hashed = tokenHash(csrfToken, this.security.sessionSecret);
    this.database.transaction(() => {
      this.database.db.prepare("INSERT INTO dashboard_csrf_tokens (session_id, token_hash, created_at) VALUES (?, ?, ?)").run(session.id, hashed, nowIso());
      this.database.db.prepare("UPDATE dashboard_sessions SET csrf_token_hash = ? WHERE id = ?").run(hashed, session.id);
      this.database.db.prepare("DELETE FROM dashboard_csrf_tokens WHERE session_id = ? AND token_hash NOT IN (SELECT token_hash FROM dashboard_csrf_tokens WHERE session_id = ? ORDER BY created_at DESC LIMIT 20)").run(session.id, session.id);
    });
    return csrfToken;
  }

  public requirePermission(principal: DashboardPrincipal, permission: DashboardPermission): void {
    if (!hasPermission(principal.role, permission)) throw new PermissionError(`Permission required: ${permission}`);
  }

  public logout(request: IncomingMessage, response: ServerResponse): void {
    const rawToken = parseCookies(request.headers.cookie ?? "").get("routecairn_session");
    if (rawToken) {
      this.database.db.prepare("UPDATE dashboard_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE token_hash = ?").run(nowIso(), tokenHash(rawToken, this.security.sessionSecret));
    }
    response.setHeader("Set-Cookie", "routecairn_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
  }

  public audit(actor: string, action: string, resourceType: string, resourceId: string | undefined, summary: string): void {
    this.database.db
      .prepare("INSERT INTO audit_events (id, actor_label, action, resource_type, resource_id, safe_summary, safe_metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, '{}', ?)")
      .run(cryptoRandomId(), clamp(actor, 120), action, resourceType, resourceId ?? null, clamp(summary, 800), nowIso());
  }

  private enforceThrottle(loginFp: string, sourceFp: string): void {
    const since = new Date(Date.now() - loginWindowMs).toISOString();
    const loginFailures = (this.database.db.prepare("SELECT COUNT(*) AS count FROM login_attempts WHERE normalized_login_fingerprint = ? AND success = 0 AND created_at >= ?").get(loginFp, since) as { count: number }).count;
    const sourceFailures = (this.database.db.prepare("SELECT COUNT(*) AS count FROM login_attempts WHERE safe_source_fingerprint = ? AND success = 0 AND created_at >= ?").get(sourceFp, since) as { count: number }).count;
    if (loginFailures >= maxFailuresPerLogin || sourceFailures >= maxFailuresPerSource) {
      throw new SessionError("Too many login attempts. Try again later.");
    }
  }

  private recordAttempt(loginFp: string, sourceFp: string, success: boolean, failureCategory?: string): void {
    this.database.transaction(() => {
      this.database.db
        .prepare("INSERT INTO login_attempts (id, normalized_login_fingerprint, safe_source_fingerprint, success, failure_category, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .run(cryptoRandomId(), loginFp, sourceFp, success ? 1 : 0, failureCategory ?? null, nowIso());
      this.database.db.prepare("DELETE FROM login_attempts WHERE id NOT IN (SELECT id FROM login_attempts ORDER BY created_at DESC LIMIT ?)").run(maxRetainedAttempts);
    });
  }

  private cookie(sessionToken: string, expiresAtMs: number): string {
    return `routecairn_session=${sessionToken}; HttpOnly; Secure; SameSite=Strict; Path=/; Expires=${new Date(expiresAtMs).toUTCString()}`;
  }
}

export class PermissionError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "PermissionError";
  }
}

export function normalizeLogin(value: string): string {
  return value.trim().toLowerCase();
}

function userSummary(database: DashboardDatabase, row: DbUserRow): DashboardUserSummary {
  const activeSessionCount = (database.db.prepare("SELECT COUNT(*) AS count FROM dashboard_sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?").get(row.id, nowIso()) as { count: number }).count;
  return {
    id: row.id,
    login: row.login,
    role: row.role,
    enabled: row.enabled === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    ...(row.last_login_at ? { lastLoginAt: row.last_login_at } : {}),
    activeSessionCount
  };
}

function token(): string {
  return randomBytes(32).toString("base64url");
}

function cryptoRandomId(): string {
  return randomUUID();
}

function tokenHash(value: string, secret: string): string {
  return createHash("sha256").update("routecairn-session-v1\0").update(secret).update("\0").update(value).digest("hex");
}

function keyedHash(value: string, secret: string): string {
  return createHash("sha256").update("routecairn-login-v1\0").update(secret).update("\0").update(value).digest("hex");
}

function sourceFingerprint(request: IncomingMessage, secret: string): string {
  const raw = String(request.socket.remoteAddress ?? "unknown");
  return keyedHash(raw, secret);
}

function safeHeader(value: string | string[] | undefined): string | null {
  if (!value) return null;
  return clamp(Array.isArray(value) ? value.join(",") : value, 200);
}

function parseCookies(header: string): Map<string, string> {
  const result = new Map<string, string>();
  for (const pair of header.split(";")) {
    const [key, ...value] = pair.trim().split("=");
    if (key) result.set(key, value.join("="));
  }
  return result;
}

function isAllowedOrigin(request: IncomingMessage, publicOrigin: string, trustProxy: boolean): boolean {
  const origin = request.headers.origin;
  if (!origin) return false;
  if (origin === publicOrigin) return true;
  if (!trustProxy) return false;
  try {
    return new URL(origin).origin === new URL(publicOrigin).origin;
  } catch {
    return false;
  }
}

interface DbUserRow {
  id: string;
  login: string;
  password_hash: string;
  role: DashboardRole;
  enabled: number;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
  locked_until: string | null;
}

interface DbSessionJoinRow {
  id: string;
  user_id: string;
  login: string;
  role: DashboardRole;
  enabled: number;
  csrf_token_hash: string;
  expires_at: string;
  last_seen_at: string;
}
