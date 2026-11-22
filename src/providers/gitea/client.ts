// A read-only client for one Gitea instance. Gitea is hosted by its users, so
// there is no one API host: the credential is the instance's address and an
// access token, and every request goes to <address>/api/v1.
//
// Every request is a GET (test/gitea.test.ts fails on anything else). The
// token should carry read scopes only; Keelson sending nothing but GET is what
// protects an older instance whose tokens have no scopes. A redirect is never
// followed: it could carry the token to another host. Requests go through
// request() (src/core/net.ts), so an instance that is only reachable inside a
// VPN, or that presents a certificate from the company's own authority, is
// reached through the network chosen for Gitea on the Networks page.
//
// Shapes are from Gitea's own API description (<instance>/swagger.v1.json);
// Forgejo serves the same API under the same paths.

import { createHash } from "node:crypto";
import { request } from "../../core/net.ts";
import { GITEA_SOURCES, type GiteaSourceKey } from "./sources.ts";
import type { Coverage } from "../../shared/api.ts";

/** API bodies are checked field by field where they're read. */
export type Json = any;

const TIMEOUT_MS = 30_000;
const MAX_IN_FLIGHT = 6;
/** The most Gitea gives per page unless its administrator changed MAX_RESPONSE_ITEMS; the instance is asked (#pageSize). */
const PAGE = 50;

export class GiteaError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const BAD_FORMAT =
  "Enter the address people open your Gitea at, starting with https:// (or http://), and an access token from that instance's Settings → Applications.";

export interface GiteaCredential {
  /** The address the instance is opened at, without a trailing slash: "https://git.example.com", or with a path when it runs under one. */
  base: string;
  token: string;
}

/**
 * The stored credential is "<address>:<token>". The address has colons of its own, and a token never does, so the
 * token is what follows the last one.
 */
export function parseCredential(credential: string): GiteaCredential | null {
  const at = credential.lastIndexOf(":");
  if (at < 0) return null;
  const token = credential.slice(at + 1).trim();
  if (!/^[A-Za-z0-9_-]{16,255}$/.test(token)) return null;
  const base = instanceAddress(credential.slice(0, at));
  return base ? { base, token } : null;
}

/** An instance's address as it is stored: scheme, host, port and any path it runs under; nothing else. Null when it isn't one. */
export function instanceAddress(text: string): string | null {
  let url: URL;
  try {
    url = new URL(text.trim());
  } catch {
    return null;
  }
  if ((url.protocol !== "https:" && url.protocol !== "http:") || !url.hostname || url.username || url.password) return null;
  // Pasted from the address bar or the API's own page: the path under which the instance runs is all that counts.
  const path = url.pathname.replace(/\/(api\/v1.*|api\/swagger.*|user\/settings.*|explore.*)?$/, "").replace(/\/+$/, "");
  return `${url.protocol}//${url.host}${path}`;
}

/** Which instance an organization is on, in its Keelson ID: organization numbers start at 1 everywhere. */
export const instanceKey = (base: string): string => createHash("sha256").update(base.toLowerCase()).digest("hex").slice(0, 8);
export const accountIdOf = (base: string, orgId: number): string => `gt_${instanceKey(base)}_${orgId}`;
export const orgIdOf = (accountId: string): number => Number(accountId.split("_")[2]);

export class GiteaClient {
  calls = 0;
  readonly coverage = new Map<GiteaSourceKey, Coverage & { key: GiteaSourceKey }>();
  readonly base: string;
  /** The organization's name once connect() has found it. */
  org = "";
  readonly #token: string;
  #inFlight = 0;
  #queue: (() => void)[] = [];

  constructor(credential: string) {
    const parsed = parseCredential(credential);
    if (!parsed) throw new GiteaError(0, BAD_FORMAT);
    this.base = parsed.base;
    this.#token = parsed.token;
  }

  /** Finds the organization an account ID names among the ones the token's user belongs to, and remembers its name. */
  async connect(accountId: string): Promise<{ id: number; name: string; fullName: string }> {
    const found = (await this.organizations()).find((o) => accountIdOf(this.base, o.id) === accountId);
    if (!found)
      throw new GiteaError(404, "The token's user no longer belongs to this organization on this instance. Replace the token with one of its owners'.");
    this.org = found.name;
    return found;
  }

  /** Organizations the token's user belongs to. */
  async organizations(): Promise<{ id: number; name: string; fullName: string }[]> {
    const orgs = await this.#pages("/user/orgs", 2000);
    return orgs.map((o) => ({ id: Number(o.id), name: String(o.username ?? o.name ?? ""), fullName: String(o.full_name || o.username || o.name || "") }));
  }

  /** One GET with the token; throws GiteaError. */
  raw(path: string): Promise<Json> {
    return this.#send(path, true).then((r) => r.body);
  }

  /** One GET without the token: what anyone who can reach the instance is told. Resolves with the status alone. */
  async anonymous(path: string): Promise<number> {
    try {
      await this.#send(path, false);
      return 200;
    } catch (e) {
      const status = (e as GiteaError).status;
      if (!status) throw e;
      return status;
    }
  }

  /** A body, or undefined (and a coverage gap) when it couldn't be read. */
  async get<T = Json>(source: GiteaSourceKey, path: string): Promise<T | undefined> {
    try {
      const body = await this.raw(path);
      this.note(source, true);
      return body as T;
    } catch (e) {
      this.note(source, false, e);
      return undefined;
    }
  }

  /** Every page of a list, or null (and a coverage gap) when it couldn't be read. `optional`: a 404 is an empty list, for what an older Gitea doesn't have. */
  async list<T = Json>(source: GiteaSourceKey, path: string, { max = 10_000, optional = false } = {}): Promise<T[] | null> {
    try {
      const out = await this.#pages(path, max);
      this.note(source, true);
      return out as T[];
    } catch (e) {
      if (optional && (e as GiteaError).status === 404) {
        this.note(source, true);
        return [];
      }
      this.note(source, false, e);
      return null;
    }
  }

  /** Records whether a source was readable. The first failure sticks, as in the other clients. */
  note(source: GiteaSourceKey, ok: boolean, err?: unknown): void {
    const prev = this.coverage.get(source);
    if (prev && !prev.ok) return;
    const { label, permission } = GITEA_SOURCES[source];
    this.coverage.set(
      source,
      ok
        ? { key: source, label, permission, ok: true }
        : {
            key: source,
            label,
            permission,
            ok: false,
            status: (err as GiteaError)?.status || 0,
            message: String((err as Error)?.message || err).slice(0, 200),
          },
    );
  }

  /**
   * Gitea pages with ?page and ?limit, and says how many there are in X-Total-Count. A list without that header is
   * over at the first page that isn't full, or that repeats the one before: some lists aren't paged at all and answer
   * every page with everything.
   */
  async #pages(path: string, max: number): Promise<Json[]> {
    const out: Json[] = [];
    const size = await this.#pageSize();
    let last = "";
    for (let page = 1; out.length < max && page <= 400; page++) {
      const { body, total } = await this.#send(`${path}${path.includes("?") ? "&" : "?"}page=${page}&limit=${size}`, true);
      const items: Json[] = Array.isArray(body) ? body : [];
      const text = JSON.stringify(items);
      if (!items.length || text === last) break;
      last = text;
      out.push(...items);
      if (total != null ? out.length >= total : items.length < size) break;
    }
    return out.slice(0, max);
  }

  /** How many items the instance gives per page: its administrator can set the most below Gitea's 50. */
  #size: Promise<number> | null = null;
  #pageSize(): Promise<number> {
    this.#size ??= this.#send("/settings/api", true).then(
      ({ body }) => Math.max(1, Math.min(PAGE, Number(body?.max_response_items) || PAGE)),
      () => PAGE,
    );
    return this.#size;
  }

  async #send(path: string, withToken: boolean): Promise<{ body: Json; total: number | null }> {
    await this.#acquire();
    try {
      for (let attempt = 0; ; attempt++) {
        this.calls++;
        let res: Response;
        try {
          res = await request(`${this.base}/api/v1${path}`, {
            method: "GET",
            // A redirect could hand the token to another host: it is reported, never followed.
            redirect: "manual",
            signal: AbortSignal.timeout(TIMEOUT_MS),
            headers: { Accept: "application/json", "User-Agent": "Keelson", ...(withToken ? { Authorization: `token ${this.#token}` } : {}) },
          });
        } catch (e) {
          if (attempt < 2) {
            await sleep(1000 * (attempt + 1));
            continue;
          }
          throw new GiteaError(0, `Network error: ${(e as Error).message}`);
        }
        if ((res.status === 429 || res.status >= 500) && attempt < 2) {
          await res.body?.cancel().catch(() => {});
          await sleep(Math.min(Number(res.headers.get("retry-after")) || attempt + 1, 30) * 1000);
          continue;
        }
        if (res.status >= 300 && res.status < 400) {
          await res.body?.cancel().catch(() => {});
          throw new GiteaError(res.status, `The instance redirected to ${hostOf(res.headers.get("location"), this.base)}. Enter the address it redirects to.`);
        }
        let json: Json = null;
        try {
          json = await res.json();
        } catch {
          /* empty or not JSON: an address that isn't a Gitea answers with a web page */
        }
        if (!res.ok) throw new GiteaError(res.status, messageOf(res.status, json));
        if (json === null) throw new GiteaError(res.status, "That address didn't answer as Gitea's API. Check the instance address.");
        const total = Number(res.headers.get("x-total-count"));
        return { body: json, total: res.headers.has("x-total-count") && Number.isFinite(total) ? total : null };
      }
    } finally {
      this.#inFlight--;
      this.#queue.shift()?.();
    }
  }

  async #acquire(): Promise<void> {
    while (this.#inFlight >= MAX_IN_FLIGHT) await new Promise<void>((r) => this.#queue.push(r));
    this.#inFlight++;
  }
}

/** Where a redirect goes, as a host: never the whole address, which can carry a sign-in token. */
function hostOf(location: string | null, base: string): string {
  try {
    return new URL(location ?? "", base).host || "another address";
  } catch {
    return "another address";
  }
}

function messageOf(status: number, body: Json): string {
  if (status === 401) return "Gitea didn't accept the token. Check that it was copied whole and hasn't been deleted.";
  if (status === 404) return "Gitea has nothing at that address (404).";
  // Gitea names the scope a token lacks: "token does not have at least one of required scope(s): [read:organization]".
  return String(body?.message || `Gitea answered ${status}`).slice(0, 200);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, Math.max(0, ms)));
