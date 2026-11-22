// Read-only GitHub client, signed in as a GitHub App. The credential is the App's
// ID and private key; Keelson signs a short JWT with the key (node:crypto, RS256),
// finds the App's installation on the organization, and asks GitHub for an
// installation token limited to read permissions. That request is the one POST
// Keelson sends to GitHub, and it creates a token that can do less than the App
// can; every other request is GET (test/github.test.ts fails on anything else).
//
// Limits: at most 8 requests in flight per scan. When the rate limit runs out,
// every request with the same App waits for the reset GitHub names (up to a
// minute); secondary limits are retried after the time GitHub asks for, and 5xx
// and network errors twice.

import { createHash, createPrivateKey, createSign, type KeyObject } from "node:crypto";
import { GITHUB_APP_PERMISSIONS, GITHUB_PERMISSION_KEYS } from "../../shared/github.ts";
import { CREDENTIAL_SEPARATOR } from "../../shared/providers.ts";
import { GITHUB_SOURCES, type GithubSourceKey } from "./sources.ts";
import type { Coverage } from "../../shared/api.ts";
import { request } from "../../core/net.ts";

export const GITHUB_API = "https://api.github.com";
const MAX_IN_FLIGHT = 8;
const TIMEOUT_MS = 30_000;
const MAX_WAIT_MS = 60_000;
const API_VERSION = "2022-11-28";
/** A raw GitHub payload; inventory.ts turns it into the typed shapes in types.ts. */
export type Json = any;

export class GithubError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface GithubApp {
  /** The App ID, or its client ID (Iv…), which GitHub accepts in the same place. */
  appId: string;
  key: KeyObject;
}

/**
 * The private key as GitHub hands it out, however it was pasted: a one-line input drops the line breaks,
 * and some tools turn them into "\n". The base64 body is rewrapped so node:crypto can read it.
 */
export function normalizePem(raw: string): string | null {
  const m = /-----BEGIN ([A-Z ]+)-----(.+?)-----END \1-----/s.exec(raw.replace(/\\n/g, "\n"));
  if (!m) return null;
  const body = m[2].replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+=*$/.test(body)) return null;
  return `-----BEGIN ${m[1]}-----\n${body.match(/.{1,64}/g)!.join("\n")}\n-----END ${m[1]}-----\n`;
}

/** "<App ID>:<private key>" as the vault stores it, or null when either part isn't usable. */
export function parseCredentials(token: string): GithubApp | null {
  const at = token.indexOf(CREDENTIAL_SEPARATOR);
  if (at < 0) return null;
  const appId = token.slice(0, at).trim();
  const pem = normalizePem(token.slice(at + 1));
  if (!/^(\d{1,20}|Iv[0-9A-Za-z.]{4,40})$/.test(appId) || !pem) return null;
  try {
    const key = createPrivateKey(pem);
    return key.asymmetricKeyType === "rsa" ? { appId, key } : null;
  } catch {
    return null;
  }
}

const b64url = (v: string | Buffer) => Buffer.from(v).toString("base64url");

/** The JWT an App signs to speak as itself. GitHub allows ten minutes; the clock is set back a minute for drift. */
export function appJwt(app: GithubApp, now = Date.now()): string {
  const iat = Math.floor(now / 1000) - 60;
  const iss = /^\d+$/.test(app.appId) ? Number(app.appId) : app.appId;
  const unsigned = `${b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${b64url(JSON.stringify({ iat, exp: iat + 9 * 60, iss }))}`;
  return `${unsigned}.${createSign("RSA-SHA256").update(unsigned).sign(app.key, "base64url")}`;
}

/** One installation of the App, as the Add accounts flow and the scan need it. */
export interface Installation {
  id: number;
  /** The App's own ID, so the scan can tell it apart from other Apps on the organization. */
  appId: number;
  /** The organization's (or user's) numeric ID and login. */
  accountId: number;
  login: string;
  type: string;
  /** "all" or "selected" repositories. */
  selection: string;
  /** What the organization granted the App: permission name → "read" or "write". */
  permissions: Record<string, string>;
}

/** Requests waiting for a rate-limit reset, per App. */
const pauses = new Map<string, number>();
/** Installation tokens last an hour; one is reused for 50 minutes across the scans of a run. */
const tokens = new Map<string, { token: string; until: number }>();
const appKey = (t: string) => createHash("sha256").update(t).digest("hex");

export class GithubClient {
  calls = 0;
  readonly coverage = new Map<GithubSourceKey, Coverage & { key: GithubSourceKey }>();
  /** The organization's login once connect() has found its installation. */
  org = "";
  installation: Installation | null = null;
  readonly #app: GithubApp;
  readonly #key: string;
  #token: string | null = null;
  #inFlight = 0;
  #queue: (() => void)[] = [];

  constructor(credential: string) {
    const app = parseCredentials(credential);
    if (!app) throw new GithubError(0, BAD_FORMAT);
    this.#app = app;
    this.#key = appKey(credential);
  }

  /** Every installation of the App: the organizations it can read. */
  async installations(): Promise<Installation[]> {
    const out: Installation[] = [];
    let path: string | null = "/app/installations?per_page=100";
    while (path && out.length < 1000) {
      const { body, next } = await this.#send(path, `Bearer ${appJwt(this.#app)}`);
      for (const i of Array.isArray(body) ? body : [])
        out.push({
          id: Number(i.id),
          appId: Number(i.app_id),
          accountId: Number(i.account?.id),
          login: String(i.account?.login ?? ""),
          type: String(i.target_type ?? i.account?.type ?? ""),
          selection: String(i.repository_selection ?? ""),
          permissions: { ...(i.permissions ?? {}) },
        });
      path = next;
    }
    return out;
  }

  /** Finds the App's installation on an organization and gets a read-only token for it. */
  async connect(orgId: number): Promise<Installation> {
    const inst = (await this.installations()).find((i) => i.accountId === orgId);
    if (!inst) throw new GithubError(404, "The GitHub App isn't installed on this organization any more. Install it again from the App's settings.");
    this.installation = inst;
    this.org = encodeURIComponent(inst.login);
    this.#token = await this.#installationToken(inst);
    return inst;
  }

  /**
   * Asks GitHub for an installation token with read access to what Keelson reads and nothing else. A
   * permission the organization didn't grant can't be asked for, so only the granted ones are named.
   */
  async #installationToken(inst: Installation): Promise<string> {
    const permissions = Object.fromEntries(GITHUB_PERMISSION_KEYS.filter((k) => inst.permissions[k]).map((k) => [k, "read"]));
    // A permission the organization accepts later needs a new token: the cached one can't read it.
    const cacheKey = `${this.#key}:${inst.id}:${Object.keys(permissions).sort().join(",")}`;
    const cached = tokens.get(cacheKey);
    if (cached && cached.until > Date.now()) return cached.token;
    const { body } = await this.#send(`/app/installations/${inst.id}/access_tokens`, `Bearer ${appJwt(this.#app)}`, { permissions });
    const token = String(body?.token ?? "");
    if (!token) throw new GithubError(0, "GitHub didn't return an installation token.");
    tokens.set(cacheKey, { token, until: Date.now() + 50 * 60_000 });
    return token;
  }

  /** GET a path with the installation token. Throws GithubError. */
  async raw(path: string): Promise<Json> {
    return (await this.page(path)).body;
  }

  /** GET one page, with the next page's path from the Link header. */
  async page(path: string): Promise<{ body: Json; next: string | null }> {
    if (!this.#token) throw new GithubError(0, "Not connected to an organization.");
    return this.#send(path, `Bearer ${this.#token}`);
  }

  /** The organization, with the settings only its administrators see. Throws when they're missing, so the probe and the scan agree. */
  async orgSettings(): Promise<Json> {
    const body = await this.raw(`/orgs/${this.org}`);
    if (typeof body?.two_factor_requirement_enabled !== "boolean")
      throw new GithubError(403, "GitHub didn't include the organization's security settings, which need the Administration permission.");
    return body;
  }

  /** GET with coverage: null when the App can't read it. */
  async get<T = Json>(source: GithubSourceKey, path: string): Promise<T | null> {
    try {
      const body = await this.raw(path);
      this.note(source, true);
      return body as T;
    } catch (e) {
      this.note(source, false, e);
      return null;
    }
  }

  /** Like get(), but a 404 means "not set up" (null) rather than unreadable (undefined), and isn't a coverage gap. */
  async getOptional<T = Json>(source: GithubSourceKey, path: string): Promise<T | null | undefined> {
    try {
      const body = await this.raw(path);
      this.note(source, true);
      return body as T;
    } catch (e) {
      if ((e as GithubError).status === 404) {
        this.note(source, true);
        return null;
      }
      this.note(source, false, e);
      return undefined;
    }
  }

  /** Every page of a list, following GitHub's Link header. `key` picks the list out of a wrapped body ({ repositories: [...] }). */
  async list<T = Json>(source: GithubSourceKey, path: string, { key, max = 10_000 }: { key?: string; max?: number } = {}): Promise<T[] | null> {
    const out: T[] = [];
    try {
      let next: string | null = `${path}${path.includes("?") ? "&" : "?"}per_page=100`;
      while (next && out.length < max) {
        const page: { body: Json; next: string | null } = await this.page(next);
        const items: T[] = key ? (page.body?.[key] ?? []) : Array.isArray(page.body) ? page.body : [];
        out.push(...items);
        next = page.next;
      }
      this.note(source, true);
      return out;
    } catch (e) {
      this.note(source, false, e);
      return null;
    }
  }

  /** Records whether a source was readable. The first failure sticks, as in the other clients. */
  note(source: GithubSourceKey, ok: boolean, err?: unknown): void {
    const prev = this.coverage.get(source);
    if (prev && !prev.ok) return;
    const { label, permission } = GITHUB_SOURCES[source];
    this.coverage.set(
      source,
      ok
        ? { key: source, label, permission, ok: true }
        : {
            key: source,
            label,
            permission,
            ok: false,
            status: (err as GithubError)?.status || 0,
            message: String((err as Error)?.message || err).slice(0, 200),
          },
    );
  }

  /** Sends one request. A body makes it the installation-token POST; everything else is GET. */
  async #send(path: string, auth: string, body?: Json): Promise<{ body: Json; next: string | null }> {
    await this.#acquire();
    try {
      for (let attempt = 0; ; attempt++) {
        this.calls++;
        let res: Response;
        try {
          res = await request(GITHUB_API + path, {
            method: body ? "POST" : "GET",
            signal: AbortSignal.timeout(TIMEOUT_MS),
            headers: {
              Authorization: auth,
              Accept: "application/vnd.github+json",
              "X-GitHub-Api-Version": API_VERSION,
              "User-Agent": "Keelson",
              ...(body ? { "Content-Type": "application/json" } : {}),
            },
            body: body ? JSON.stringify(body) : undefined,
          });
        } catch (e) {
          if (attempt < 2) {
            await sleep(1000 * (attempt + 1));
            continue;
          }
          throw new GithubError(0, `Network error: ${(e as Error).message}`);
        }
        // The primary limit says when it resets; secondary limits say how long to wait.
        const limited = res.status === 429 || (res.status === 403 && (res.headers.get("x-ratelimit-remaining") === "0" || res.headers.has("retry-after")));
        if (limited && attempt < 3) {
          const reset = Number(res.headers.get("x-ratelimit-reset")) * 1000;
          const wait = res.headers.has("retry-after") ? Number(res.headers.get("retry-after")) * 1000 : reset - Date.now();
          if (wait <= MAX_WAIT_MS) {
            pauses.set(this.#key, Math.max(pauses.get(this.#key) || 0, Date.now() + Math.max(wait, 1000)));
            await sleep(Math.max(wait, 1000));
            continue;
          }
        }
        if (res.status >= 500 && attempt < 2) {
          await sleep(1000 * (attempt + 1));
          continue;
        }
        let json: Json = null;
        try {
          json = await res.json();
        } catch {
          /* empty or non-JSON body */
        }
        if (!res.ok)
          throw new GithubError(res.status, limited ? "GitHub's rate limit for this App ran out. The next scan carries on." : messageOf(res.status, json));
        return { body: json, next: nextPage(res.headers.get("link")) };
      }
    } finally {
      this.#release();
    }
  }

  async #acquire(): Promise<void> {
    while (this.#inFlight >= MAX_IN_FLIGHT) await new Promise<void>((r) => this.#queue.push(r));
    this.#inFlight++;
    const until = pauses.get(this.#key) || 0;
    if (until > Date.now()) await sleep(until - Date.now());
  }

  #release(): void {
    this.#inFlight--;
    this.#queue.shift()?.();
  }
}

export const BAD_FORMAT =
  "Enter the GitHub App's ID (a number, under the App's General settings) and the whole private key file it generated, from -----BEGIN to -----END.";

function messageOf(status: number, body: Json): string {
  if (status === 401) return "GitHub didn't accept the App's private key. Check that it belongs to this App ID and hasn't been deleted.";
  return String(body?.message || `GitHub answered ${status}`).slice(0, 200);
}

/** The path of the rel="next" page in a Link header, or null on the last page. */
export function nextPage(link: string | null): string | null {
  const m = link ? /<([^>]+)>;\s*rel="next"/.exec(link) : null;
  if (!m) return null;
  const u = new URL(m[1]);
  return u.origin === GITHUB_API ? u.pathname + u.search : null;
}

/** What the App's settings call each permission Keelson asks for, for messages. */
export const permissionLabel = (k: string) => (GITHUB_APP_PERMISSIONS as Record<string, string>)[k] ?? k;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, Math.max(0, ms)));
