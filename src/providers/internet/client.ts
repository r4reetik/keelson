// The services an internet scan (Sonar) asks, all with GET: crt.sh for certificate
// transparency logs, and Shodan for what it has seen on an address (its full API
// with a key, its free InternetDB without one) and the subdomains it knows. None of
// them touches the entity's own hosts. Public DNS goes through `doh` in
// src/core/cloudflare.ts, like the Cloudflare scan's lookups.
//
// What is sent: the entity's domain names to crt.sh and Shodan, and its public
// addresses to Shodan. The key goes in the query string because that is the only
// way Shodan's API accepts it; it never appears in an error message or a log line.
//
// Limits: Shodan's API is asked at most once a second (its documented rate), InternetDB
// four times a second; crt.sh one domain at a time, a second and a half apart, with up to
// two retries, since it is often slow or busy. Answers are read up to a size limit.

import { HOMEPAGE } from "../../meta.ts";
import { sleep } from "../../core/cloudflare.ts";
import { INTERNET_SOURCES, type InternetSourceKey } from "./sources.ts";
import type { Coverage } from "../../shared/api.ts";
import type { ShodanService, ShodanView, ShodanVuln } from "./types.ts";
import { request } from "../../core/net.ts";

export const CRTSH = "https://crt.sh";
export const SHODAN_API = "https://api.shodan.io";
export const INTERNETDB = "https://internetdb.shodan.io";

const USER_AGENT = `Keelson (+${HOMEPAGE})`;
const MAX_BYTES = 32 * 1024 * 1024;
/** Milliseconds between requests to each service, and before crt.sh's one retry. Tests set them to 0. */
export const pacing = { shodan: 1000, internetdb: 250, crtsh: 1500, crtshRetry: 5000 };
const paceOf = (host: string): number | null =>
  host === "api.shodan.io" ? pacing.shodan : host === "internetdb.shodan.io" ? pacing.internetdb : host === "crt.sh" ? pacing.crtsh : null;
/** crt.sh is free and shared, and on a real scan it refused or timed out on a few domains in a row and answered them minutes later. */
const CRTSH_ATTEMPTS = 3;

export class InternetError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** One certificate log entry as crt.sh lists it. */
export interface CrtEntry {
  id: number;
  issuer_name: string;
  name_value: string;
  serial_number?: string;
  not_before: string;
  not_after: string;
  entry_timestamp: string;
}

type Json = any;

export class InternetClient {
  calls = 0;
  readonly coverage = new Map<InternetSourceKey, Coverage & { key: InternetSourceKey }>();
  readonly #key: string;
  readonly #last = new Map<string, Promise<void>>();

  constructor(shodanKey: string) {
    this.#key = shodanKey.trim();
  }

  get hasKey(): boolean {
    return !!this.#key;
  }

  /** Records whether a source was readable. The first failure sticks, as in the other clients. */
  note(source: InternetSourceKey, ok: boolean, err?: unknown): void {
    const prev = this.coverage.get(source);
    if (prev && !prev.ok) return;
    const { label, permission } = INTERNET_SOURCES[source];
    this.coverage.set(
      source,
      ok
        ? { key: source, label, permission, ok: true }
        : {
            key: source,
            label,
            permission,
            ok: false,
            status: (err as InternetError)?.status || 0,
            message: String((err as Error)?.message || err).slice(0, 200),
          },
    );
  }

  /** Certificates in the logs for names under a domain, without expired ones. */
  async certificates(domain: string): Promise<CrtEntry[]> {
    const url = `${CRTSH}/?q=${encodeURIComponent(`%.${domain}`)}&output=json&exclude=expired`;
    for (let attempt = 0; ; attempt++) {
      try {
        const body = await this.#get(url, "crt.sh", 90_000);
        return Array.isArray(body) ? (body as CrtEntry[]) : [];
      } catch (e) {
        if (attempt >= CRTSH_ATTEMPTS - 1 || (e as InternetError).status === 404) throw e;
        // Longer each time: 5 seconds, then 15.
        await sleep(pacing.crtshRetry * (attempt * 2 + 1));
      }
    }
  }

  /** What Shodan has seen on an address, or `{ seen: false }` when it has nothing. */
  async host(ip: string): Promise<(ShodanView & { seen: true }) | { seen: false }> {
    try {
      if (this.#key)
        return {
          seen: true,
          ...fromApi(await this.#get(`${SHODAN_API}/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(this.#key)}`, "Shodan")),
        };
      return { seen: true, ...fromInternetDb(await this.#get(`${INTERNETDB}/${encodeURIComponent(ip)}`, "Shodan InternetDB")) };
    } catch (e) {
      if ((e as InternetError).status === 404) return { seen: false };
      throw e;
    }
  }

  /** Subdomains Shodan knows for a domain. Needs a key with query credits. */
  async subdomains(domain: string): Promise<string[]> {
    const body = await this.#get(`${SHODAN_API}/dns/domain/${encodeURIComponent(domain)}?key=${encodeURIComponent(this.#key)}`, "Shodan");
    return (Array.isArray(body?.subdomains) ? body.subdomains : []).map((s: unknown) => `${String(s).toLowerCase()}.${domain}`);
  }

  /** The key's plan, to verify it. */
  async plan(): Promise<string> {
    const body = await this.#get(`${SHODAN_API}/api-info?key=${encodeURIComponent(this.#key)}`, "Shodan");
    return String(body?.plan ?? "");
  }

  /** One GET, paced per host, with the URL (and so the key) kept out of every error. */
  async #get(url: string, service: string, timeout = 30_000): Promise<Json> {
    const host = new URL(url).hostname;
    await this.#pace(host);
    this.calls++;
    let res: Response;
    try {
      res = await request(url, { method: "GET", headers: { accept: "application/json", "user-agent": USER_AGENT }, signal: AbortSignal.timeout(timeout) });
    } catch (e) {
      throw new InternetError(0, `${service} couldn't be reached (${(e as Error)?.name === "TimeoutError" ? "timed out" : "network error"})`);
    }
    const gap = paceOf(host);
    if (res.status === 429 && gap != null) {
      await sleep(Math.max(gap, 500) * 2);
      return this.#get(url, service, timeout);
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => {});
      throw new InternetError(res.status, statusMessage(service, res.status));
    }
    const text = await readCapped(res, MAX_BYTES);
    try {
      return JSON.parse(text);
    } catch {
      throw new InternetError(res.status, `${service} sent an answer Keelson couldn't read`);
    }
  }

  /** Requests to one host wait their turn so they stay under its rate. */
  async #pace(host: string): Promise<void> {
    const gap = paceOf(host);
    if (!gap) return;
    const prev = this.#last.get(host) ?? Promise.resolve();
    const mine = prev.then(async () => {
      await sleep(gap);
    });
    this.#last.set(host, mine);
    await prev;
  }
}

function statusMessage(service: string, status: number): string {
  if (status === 401 || status === 403) return `${service} refused the key (${status}). Check it in your Shodan account, or remove it to use InternetDB.`;
  if (status === 402) return `${service} needs a plan with query credits for this (402)`;
  return `${service} answered ${status}`;
}

async function readCapped(res: Response, max: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel().catch(() => {});
      throw new InternetError(res.status, "The answer was too large to read");
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);
const ports = (v: unknown): number[] =>
  [...new Set((Array.isArray(v) ? v : []).map(Number).filter((p) => Number.isInteger(p) && p > 0 && p < 65536))].sort((a, b) => a - b);
const hostnames = (v: unknown): string[] => (Array.isArray(v) ? v : []).map((h) => String(h).toLowerCase().replace(/\.$/, ""));

/** Shodan's full host answer. Banners, certificates and page content are dropped here: only ports, products and versions are kept. */
function fromApi(b: Json): ShodanView {
  const services: ShodanService[] = (Array.isArray(b?.data) ? b.data : []).map((d: Json) => ({
    port: Number(d?.port),
    transport: str(d?.transport),
    product: str(d?.product),
    version: str(d?.version),
  }));
  const vulns = new Map<string, ShodanVuln>();
  for (const id of Array.isArray(b?.vulns) ? b.vulns : []) vulns.set(String(id), { id: String(id), cvss: null });
  for (const d of Array.isArray(b?.data) ? b.data : [])
    for (const [id, v] of Object.entries((d?.vulns ?? {}) as Record<string, Json>)) {
      const cvss = num(v?.cvss);
      const cur = vulns.get(id);
      vulns.set(id, { id, cvss: cur?.cvss != null && (cvss == null || cur.cvss > cvss) ? cur.cvss : cvss });
    }
  return {
    ports: ports(b?.ports ?? services.map((s) => s.port)),
    services: services.filter((s) => Number.isInteger(s.port)),
    vulns: [...vulns.values()].filter((v) => /^CVE-\d{4}-\d+$/.test(v.id)),
    hostnames: hostnames([...(b?.hostnames ?? []), ...(b?.domains ?? [])]),
    lastSeen: str(b?.last_update),
    via: "api",
  };
}

/** InternetDB: ports, hostnames and CVE IDs, with no products or scores. */
function fromInternetDb(b: Json): ShodanView {
  return {
    ports: ports(b?.ports),
    services: [],
    vulns: (Array.isArray(b?.vulns) ? b.vulns : [])
      .map((id: unknown) => ({ id: String(id), cvss: null }))
      .filter((v: ShodanVuln) => /^CVE-\d{4}-\d+$/.test(v.id)),
    hostnames: hostnames(b?.hostnames),
    lastSeen: null,
    via: "internetdb",
  };
}
