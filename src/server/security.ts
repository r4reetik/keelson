// Authentication and request hardening.
//
// - Users sign in with a username and password (src/store/users.ts). Sessions
//   are HttpOnly SameSite=Strict cookies, kept in memory and checked against the
//   user on every request, so a removed user or a changed role applies at once.
// - Until the first admin exists, anyone who can reach Keelson could create it.
//   Off this machine that needs the setup code printed in Keelson's log.
// - KEELSON_AUTH=none turns sign-in off: a proxy in front decides who gets in,
//   and everyone acts as an admin. On loopback the Host header must then be a
//   loopback name, which blocks DNS-rebinding attacks from web pages.
// - Sign-in and setup attempts are rate-limited per address and overall.
// - Every state-changing request must be JSON and same-origin (CSRF).

import { randomBytes } from "node:crypto";
import type { Context, MiddlewareHandler } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import type { UserRepo, User } from "../store/users.ts";
import type { SessionUser } from "../shared/api.ts";
import { hashPassword, sameCode, setupCode, verifyPassword } from "./passwords.ts";

export interface AuthOptions {
  /** No sign-in (KEELSON_AUTH=none): an authenticating proxy in front decides who gets in. */
  insecureNoAuth: boolean;
  loopback: boolean;
  trustProxy: boolean;
  allowedHosts: string[];
}

const SESSION_COOKIE = "keelson_session";
const SESSION_TTL_MS = 12 * 3600_000;
const LOGIN_WINDOW_MS = 15 * 60_000;
const LOGIN_MAX_ATTEMPTS = 10;
/** Failed logins from all addresses together, so many addresses can't guess (or burn CPU) in parallel. */
const LOGIN_MAX_FAILURES_TOTAL = 100;
/** Addresses remembered for rate limiting; the oldest are forgotten first. */
const LOGIN_TRACKED_IPS = 10_000;
/** A session's cookie is re-issued once it has slid this far, so active users stay signed in. */
const SESSION_REFRESH_MS = 3600_000;

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/** Who everyone is when sign-in is off: the proxy has already decided they may get in. */
const PROXY_USER: SessionUser = { id: 0, username: "", name: null, role: "admin", mustChangePassword: false };

export const sessionUser = (u: User): SessionUser => ({ id: u.id, username: u.username, name: u.name, role: u.role, mustChangePassword: u.mustChangePassword });

export interface NewAdmin {
  username: string;
  name: string | null;
  password: string;
  code: string;
}

export class Auth {
  readonly required: boolean;
  readonly #opts: AuthOptions;
  readonly #users: UserRepo;
  readonly #sessions = new Map<string, { userId: number; exp: number }>();
  readonly #attempts = new Map<string, number[]>();
  #failures: number[] = [];
  /** Needed to create the first admin from anywhere but this machine; printed at startup. Null once someone exists. */
  #setupCode: string | null;

  constructor(opts: AuthOptions, users: UserRepo) {
    this.#opts = opts;
    this.#users = users;
    this.required = !opts.insecureNoAuth;
    this.#setupCode = this.required && users.count() === 0 ? setupCode() : null;
  }

  /** The setup code to print, while the first admin hasn't been created. */
  get setupCode(): string | null {
    return this.setupRequired ? this.#setupCode : null;
  }

  /** Nobody can sign in yet. */
  get setupRequired(): boolean {
    if (!this.#setupCode) return false;
    if (this.#users.count() > 0) this.#setupCode = null;
    return !!this.#setupCode;
  }

  /**
   * Whether creating the admin from this request needs the setup code: always, unless Keelson listens
   * on loopback and the request names this machine (so a web page can't rebind its name to it).
   */
  setupCodeRequired(c: Context): boolean {
    return !(this.#opts.loopback && this.#localHost(c));
  }

  #localHost(c: Context): boolean {
    const hostname = (c.req.header("host") || "").toLowerCase().replace(/:\d+$/, "");
    return LOOPBACK_HOSTS.has(hostname) || this.#opts.allowedHosts.includes(hostname);
  }

  /** The signed-in user, or null. Read from the database on every request, so changes apply at once. */
  user(c: Context): SessionUser | null {
    if (!this.required) return PROXY_USER;
    const id = getCookie(c, SESSION_COOKIE);
    if (!id) return null;
    const s = this.#sessions.get(id);
    const now = Date.now();
    const user = s && s.exp >= now ? this.#users.get(s.userId) : null;
    if (!s || !user) {
      this.#sessions.delete(id);
      return null;
    }
    // Sliding expiry: the cookie is renewed with it, or the browser would drop it 12 hours after sign-in.
    if (s.exp - now < SESSION_TTL_MS - SESSION_REFRESH_MS) {
      s.exp = now + SESSION_TTL_MS;
      this.#setCookie(c, id);
    }
    return sessionUser(user);
  }

  #setCookie(c: Context, id: string): void {
    setCookie(c, SESSION_COOKIE, id, {
      httpOnly: true,
      sameSite: "Strict",
      path: "/",
      secure: isHttps(c, this.#opts.trustProxy),
      maxAge: SESSION_TTL_MS / 1000,
    });
  }

  /** Starts a session for a user and returns its ID (the cookie's value). */
  startSession(userId: number): string {
    const now = Date.now();
    for (const [sid, s] of this.#sessions) if (s.exp < now) this.#sessions.delete(sid);
    const id = randomBytes(32).toString("base64url");
    this.#sessions.set(id, { userId, exp: now + SESSION_TTL_MS });
    return id;
  }

  #signIn(c: Context, user: User): void {
    this.#setCookie(c, this.startSession(user.id));
    this.#users.signedIn(user.id);
  }

  /** Signs a user out everywhere, except the session making the request when `keep` is given. */
  endSessions(userId: number, keep?: Context): void {
    const current = keep ? getCookie(keep, SESSION_COOKIE) : undefined;
    for (const [sid, s] of this.#sessions) if (s.userId === userId && sid !== current) this.#sessions.delete(sid);
  }

  /** "Too many attempts" while this address, or everyone together, has failed too often recently. */
  #limited(c: Context): string | null {
    const since = Date.now() - LOGIN_WINDOW_MS;
    const recent = (this.#attempts.get(clientIp(c, this.#opts.trustProxy)) || []).filter((t) => t > since);
    this.#failures = this.#failures.filter((t) => t > since);
    return recent.length >= LOGIN_MAX_ATTEMPTS || this.#failures.length >= LOGIN_MAX_FAILURES_TOTAL ? "Too many attempts. Try again in a few minutes." : null;
  }

  #failed(c: Context): void {
    const ip = clientIp(c, this.#opts.trustProxy);
    const now = Date.now();
    const recent = (this.#attempts.get(ip) || []).filter((t) => t > now - LOGIN_WINDOW_MS);
    this.#attempts.delete(ip); // re-insert, so the map stays in least-recent order
    this.#attempts.set(ip, [...recent, now]);
    if (this.#attempts.size > LOGIN_TRACKED_IPS) this.#attempts.delete(this.#attempts.keys().next().value as string);
    this.#failures.push(now);
  }

  /** Returns null on success, or an error message. An unknown username takes as long as a wrong password. */
  async login(c: Context, username: string, password: string): Promise<string | null> {
    if (!this.required) return null;
    const limited = this.#limited(c);
    if (limited) return limited;
    const user = this.#users.byUsername(username);
    const ok = await verifyPassword(password, user ? this.#users.passwordHash(user.id) : null);
    if (!user || !ok) {
      this.#failed(c);
      return "Incorrect username or password.";
    }
    this.#attempts.delete(clientIp(c, this.#opts.trustProxy));
    this.#signIn(c, user);
    return null;
  }

  /** Creates the first admin and signs them in. Returns null on success, or an error message. */
  async setup(c: Context, admin: NewAdmin): Promise<string | null> {
    if (!this.setupRequired) return "An admin account already exists. Sign in instead.";
    const limited = this.#limited(c);
    if (limited) return limited;
    if (this.setupCodeRequired(c) && !sameCode(admin.code, this.#setupCode!)) {
      this.#failed(c);
      return admin.code.trim() ? "That setup code isn't right. Copy it from Keelson's log." : "Enter the setup code from Keelson's log.";
    }
    const user = this.#users.createFirst({
      username: admin.username,
      name: admin.name,
      role: "admin",
      passwordHash: await hashPassword(admin.password),
      mustChangePassword: false,
      createdBy: null,
    });
    if (!user) return "An admin account already exists. Sign in instead.";
    this.#setupCode = null;
    this.#signIn(c, user);
    return null;
  }

  /** Checks the signed-in user's current password before it's changed, under the same limits as signing in. */
  async checkPassword(c: Context, userId: number, password: string): Promise<string | null> {
    const limited = this.#limited(c);
    if (limited) return limited;
    if (await verifyPassword(password, this.#users.passwordHash(userId))) return null;
    this.#failed(c);
    return "Your current password isn't right.";
  }

  logout(c: Context): void {
    const id = getCookie(c, SESSION_COOKIE);
    if (id) this.#sessions.delete(id);
    deleteCookie(c, SESSION_COOKIE, { path: "/" });
  }

  /** Host-header allowlist (sign-in off on loopback) and CSRF protection for state-changing requests. */
  guard(): MiddlewareHandler {
    return async (c, next) => {
      const host = (c.req.header("host") || "").toLowerCase();
      if (this.#opts.loopback && !this.required && !this.#localHost(c)) {
        return c.text("Forbidden host", 403);
      }
      if (!["GET", "HEAD", "OPTIONS"].includes(c.req.method)) {
        if (!(c.req.header("content-type") || "").toLowerCase().startsWith("application/json")) return c.json({ error: "Expected application/json" }, 415);
        const site = c.req.header("sec-fetch-site");
        if (site && site !== "same-origin" && site !== "none") return c.json({ error: "Cross-site request blocked" }, 403);
        const origin = c.req.header("origin");
        if (origin) {
          let originHost = "";
          try {
            originHost = new URL(origin).host.toLowerCase();
          } catch {
            /* invalid */
          }
          const forwarded = this.#opts.trustProxy ? (c.req.header("x-forwarded-host") || "").toLowerCase() : "";
          if (originHost !== host && originHost !== forwarded) return c.json({ error: "Cross-origin request blocked" }, 403);
        }
      }
      await next();
    };
  }
}

export function securityHeaders(): MiddlewareHandler {
  return async (c, next) => {
    await next();
    c.header(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
    );
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "no-referrer");
    c.header("Cross-Origin-Opener-Policy", "same-origin");
    c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    if (c.req.path.startsWith("/api/")) c.header("Cache-Control", "no-store");
  };
}

/**
 * The address login limits apply to. Behind a trusted proxy that's the last X-Forwarded-For
 * entry: the one the proxy itself added. Earlier entries come from the client and can be forged.
 */
function clientIp(c: Context, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = c.req.header("x-forwarded-for");
    if (xff) return xff.split(",").at(-1)?.trim() || "unknown";
  }
  const env = c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined;
  return env?.incoming?.socket?.remoteAddress || "unknown";
}

function isHttps(c: Context, trustProxy: boolean): boolean {
  if (trustProxy && c.req.header("x-forwarded-proto") === "https") return true;
  return new URL(c.req.url).protocol === "https:";
}
