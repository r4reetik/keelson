// A read-only client for one GitLab instance: gitlab.com, or one its users host
// (GitLab Self-Managed, Dedicated). The credential is the instance's address
// and an access token, and every request goes to <address>/api/v4.
//
// Every request is a GET (test/gitlab.test.ts fails on anything else), with the
// token in the PRIVATE-TOKEN header and never in an address. The token should
// have the read_api scope only, which can change nothing; Keelson sending
// nothing but GET is what protects a token that was given more. A redirect is
// never followed: it could carry the token to another host. Requests go through
// request() (src/core/net.ts), so an instance behind a VPN, or with a
// certificate from the company's own authority, is reached through the network
// chosen for GitLab on the Networks page.
//
// Shapes are from GitLab's REST API reference (https://docs.gitlab.com/api/),
// and the public ones were read from gitlab.com on 2026-11-20.

import { createHash } from "node:crypto";
import { request } from "../../core/net.ts";
import { GITLAB_SOURCES, type GitlabSourceKey } from "./sources.ts";
import type { Coverage } from "../../shared/api.ts";

/** API bodies are checked field by field where they're read. */
export type Json = any;

const TIMEOUT_MS = 30_000;
const MAX_IN_FLIGHT = 6;
const PAGE = 100;

export class GitlabError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const BAD_FORMAT = "Enter the address you open GitLab at (https://gitlab.com, or your own instance's) and an access token with the read_api scope.";

export interface GitlabCredential {
  /** The address the instance is opened at, without a trailing slash: "https://gitlab.com", or with a path when it runs under one. */
  base: string;
  token: string;
}

/** The stored credential is "<address>:<token>": an address has colons of its own and a token never does, so the token follows the last one. */
export function parseCredential(credential: string): GitlabCredential | null {
  const at = credential.lastIndexOf(":");
  if (at < 0) return null;
  const token = credential.slice(at + 1).trim();
  if (!/^[A-Za-z0-9_.-]{16,300}$/.test(token)) return null;
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
  // Pasted from the address bar: only where the instance runs counts, not the page that was open.
  const path = url.pathname.replace(/\/(api\/v4|-|groups|users|dashboard|explore|admin|projects)(\/.*)?$/, "").replace(/\/+$/, "");
  return `${url.protocol}//${url.host}${path}`;
}

/** Which instance a group is on, in its Keelson ID: group numbers are only unique within one. */
export const instanceKey = (base: string): string => createHash("sha256").update(base.toLowerCase()).digest("hex").slice(0, 8);
export const accountIdOf = (base: string, groupId: number): string => `gl_${instanceKey(base)}_${groupId}`;
export const groupIdOf = (accountId: string): number => Number(accountId.split("_")[2]);

export class GitlabClient {
  calls = 0;
  readonly coverage = new Map<GitlabSourceKey, Coverage & { key: GitlabSourceKey }>();
  readonly base: string;
  /** The group's number and full path once connect() has found it. */
  groupId = 0;
  org = "";
  readonly #token: string;
  #inFlight = 0;
  #queue: (() => void)[] = [];

  constructor(credential: string) {
    const parsed = parseCredential(credential);
    if (!parsed) throw new GitlabError(0, BAD_FORMAT);
    this.base = parsed.base;
    this.#token = parsed.token;
  }

  /** Reads the group an account ID names, and remembers its number and path. */
  async connect(accountId: string): Promise<Json> {
    const id = groupIdOf(accountId);
    if (accountIdOf(this.base, id) !== accountId)
      throw new GitlabError(404, "This group is on another GitLab instance than the token's. Replace the credential with one for its instance.");
    let body: Json;
    try {
      body = await this.raw(`/groups/${id}?with_projects=false`);
    } catch (e) {
      if ((e as GitlabError).status === 404)
        throw new GitlabError(404, "The token can no longer read this group. Replace it with one that has access to the group.");
      throw e;
    }
    this.groupId = id;
    this.org = String(body?.full_path ?? "");
    return body;
  }

  /** Top-level groups the token can read as at least a Reporter: the ones worth scanning with it. */
  async groups(): Promise<{ id: number; path: string; name: string }[]> {
    const { items } = await this.#pages("/groups?top_level_only=true&min_access_level=20&order_by=path", 2000);
    return items.map((g) => ({ id: Number(g.id), path: String(g.full_path ?? g.path ?? ""), name: String(g.full_name || g.name || g.full_path || "") }));
  }

  /** One GET; throws GitlabError. */
  raw(path: string): Promise<Json> {
    return this.send(path).then((r) => r.body);
  }

  /** A body, or undefined (and a coverage gap) when it couldn't be read. */
  async get<T = Json>(source: GitlabSourceKey, path: string): Promise<T | undefined> {
    try {
      const body = await this.raw(path);
      this.note(source, true);
      return body as T;
    } catch (e) {
      this.note(source, false, e);
      return undefined;
    }
  }

  /**
   * Every page of a list, or null (and a coverage gap) when it couldn't be read. `absentOn`: the answers that mean
   * the instance doesn't have the feature at all (group webhooks and approval rules are Premium, and a plan without
   * them answers 404), which is an empty list marked as such (`absent`), not a gap. A 403 elsewhere is a role that is
   * too low, which is a gap.
   */
  async list<T = Json>(source: GitlabSourceKey, path: string, { max = 20_000, absentOn = [] as number[] } = {}): Promise<(T[] & { absent?: boolean }) | null> {
    try {
      const { items } = await this.#pages(path, max);
      this.note(source, true);
      return items as T[];
    } catch (e) {
      if (absentOn.includes((e as GitlabError).status)) {
        this.note(source, true);
        return Object.assign([] as T[], { absent: true });
      }
      this.note(source, false, e);
      return null;
    }
  }

  /** Records whether a source was readable. The first failure sticks, as in the other clients. */
  note(source: GitlabSourceKey, ok: boolean, err?: unknown): void {
    const prev = this.coverage.get(source);
    if (prev && !prev.ok) return;
    const { label, permission } = GITLAB_SOURCES[source];
    this.coverage.set(
      source,
      ok
        ? { key: source, label, permission, ok: true }
        : {
            key: source,
            label,
            permission,
            ok: false,
            status: (err as GitlabError)?.status || 0,
            message: String((err as Error)?.message || err).slice(0, 200),
          },
    );
  }

  /** GitLab pages with ?page and ?per_page, and names the next page in X-Next-Page (empty on the last). */
  async #pages(path: string, max: number): Promise<{ items: Json[] }> {
    const items: Json[] = [];
    let page = "1";
    for (let n = 0; page && items.length < max && n < 500; n++) {
      const { body, next } = await this.send(`${path}${path.includes("?") ? "&" : "?"}per_page=${PAGE}&page=${page}`);
      const got: Json[] = Array.isArray(body) ? body : [];
      items.push(...got);
      page = got.length ? next : "";
    }
    return { items: items.slice(0, max) };
  }

  /** One request, with what its headers say comes next: the next page's number, and the next page's address for lists paged by key. */
  async send(path: string): Promise<{ body: Json; next: string; link: string | null }> {
    while (this.#inFlight >= MAX_IN_FLIGHT) await new Promise<void>((r) => this.#queue.push(r));
    this.#inFlight++;
    try {
      for (let attempt = 0; ; attempt++) {
        this.calls++;
        let res: Response;
        try {
          res = await request(`${this.base}/api/v4${path}`, {
            method: "GET",
            // A redirect could hand the token to another host: it is reported, never followed.
            redirect: "manual",
            signal: AbortSignal.timeout(TIMEOUT_MS),
            headers: { Accept: "application/json", "User-Agent": "Keelson", "PRIVATE-TOKEN": this.#token },
          });
        } catch (e) {
          if (attempt < 2) {
            await sleep(1000 * (attempt + 1));
            continue;
          }
          throw new GitlabError(0, `Network error: ${(e as Error).message}`);
        }
        if ((res.status === 429 || res.status >= 500) && attempt < 3) {
          await res.body?.cancel().catch(() => {});
          await sleep(Math.min(Number(res.headers.get("retry-after")) || 2 ** attempt, 60) * 1000);
          continue;
        }
        if (res.status >= 300 && res.status < 400) {
          await res.body?.cancel().catch(() => {});
          throw new GitlabError(res.status, `The instance redirected to ${hostOf(res.headers.get("location"), this.base)}. Enter the address it redirects to.`);
        }
        let json: Json = null;
        try {
          json = await res.json();
        } catch {
          /* empty or not JSON: an address that isn't a GitLab answers with a web page */
        }
        if (!res.ok) throw new GitlabError(res.status, messageOf(res.status, json));
        if (json === null) throw new GitlabError(res.status, "That address didn't answer as GitLab's API. Check the instance address.");
        return { body: json, next: res.headers.get("x-next-page") ?? "", link: nextLink(res.headers.get("link"), this.base) };
      }
    } finally {
      this.#inFlight--;
      this.#queue.shift()?.();
    }
  }
}

/** The path (under /api/v4) of a Link header's rel="next" page, when it is on this instance; null on the last page. */
function nextLink(link: string | null, base: string): string | null {
  const m = link ? /<([^>]+)>;\s*rel="next"/.exec(link) : null;
  if (!m) return null;
  try {
    const u = new URL(m[1]);
    const root = new URL(`${base}/api/v4`);
    return u.host === root.host && u.pathname.startsWith(root.pathname) ? u.pathname.slice(root.pathname.length) + u.search : null;
  } catch {
    return null;
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
  if (status === 401) return "GitLab didn't accept the token. Check that it was copied whole, hasn't expired and hasn't been revoked.";
  // GitLab names the scope a token lacks: {"error":"insufficient_scope","error_description":"…","scope":"api read_api"}.
  const text = body?.error_description || body?.message || body?.error;
  return String(typeof text === "string" ? text : text ? JSON.stringify(text) : `GitLab answered ${status}`).slice(0, 200);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, Math.max(0, ms)));
