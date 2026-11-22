// How a request finds its network. The Networks page keeps a list of networks
// (a proxy into a VPN or zero trust network, the certificates it signs with)
// and which one each platform's requests use; this turns that into the Route the
// scanner and the account routes send through (src/core/net.ts).
//
// A platform follows the default unless it names a network of its own or the
// machine's own connection. The default also carries what Keelson reads for
// itself: vulnerability catalogs, support dates, update checks, alerts.

import { createHash, X509Certificate } from "node:crypto";
import type { TokenVault } from "./config.ts";
import { forgetRoute, NetworkError, request, through, type Route } from "./core/net.ts";
import type { Network, Repo } from "./store/repo.ts";
import type { NetworkCertificate, NetworkReach, NetworkTestResponse } from "./shared/networks.ts";
import { PROVIDER_INFO, PROVIDERS, type ProviderId } from "./shared/providers.ts";
import { PROVIDER } from "./providers/index.ts";

const PEM = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/** The certificates in a PEM text. Throws when one can't be read. */
export function certificatesIn(pem: string): X509Certificate[] {
  return (pem.match(PEM) ?? []).map((block) => new X509Certificate(block));
}

/** What a network's certificates are, to show: who they name, until when, and a fingerprint to compare. */
export function describeCertificates(pem: string | null, now = Date.now()): NetworkCertificate[] {
  if (!pem) return [];
  try {
    return certificatesIn(pem).map((c) => {
      const expires = new Date(c.validTo);
      // "CN=Example Root CA" out of a subject with one part per line.
      const name = /^CN=(.+)$/m.exec(c.subject)?.[1] ?? /^O=(.+)$/m.exec(c.subject)?.[1] ?? c.subject.replace(/\n/g, ", ");
      return { subject: name, expires: expires.toISOString(), expired: expires.getTime() < now, fingerprint: c.fingerprint256 };
    });
  } catch {
    return [];
  }
}

/** The route a network gives, with its proxy password read from the vault. `password` stands in for the stored one (a test of unsaved settings). */
export function routeOf(n: Omit<Network, "id" | "updatedAt"> & { id?: number }, vault: TokenVault, password?: string | null): Route {
  const secret = password !== undefined ? password : n.secretId ? (vault.get(n.secretId)?.token ?? null) : null;
  const proxy = n.proxy ? { ...n.proxy, password: n.proxy.username != null ? secret || null : null } : null;
  // Connections are kept per key, so anything that changes where or how they go must change it.
  const key = createHash("sha256")
    .update(JSON.stringify([n.id ?? null, n.name, proxy, n.ca]))
    .digest("hex")
    .slice(0, 24);
  return { key, name: n.name, proxy, ca: n.ca };
}

/** The route a platform's requests take (null: the machine's own connection). Without a platform, the default route. */
export function routeFor(repo: Repo, vault: TokenVault, provider: ProviderId | null): Route | null {
  const use = repo.networks.use();
  const own = provider ? use.providers[provider] : undefined;
  if (own === "direct") return null;
  const id = own ?? use.default;
  const network = id == null ? null : repo.networks.get(id);
  return network ? routeOf(network, vault) : null;
}

/** Drops vault entries nothing uses any more: credentials of removed accounts, passwords of removed or changed networks. */
export function pruneVault(repo: Repo, vault: TokenVault): void {
  vault.retain(new Set([...repo.accounts.list().map((a) => a.tokenId), ...repo.networks.secretIds()]));
}

/** Closes the connections kept for a network as it was, after it changed or was removed. */
export const forgetNetwork = (n: Network, vault: TokenVault): void => forgetRoute(routeOf(n, vault).key);

/**
 * Where a platform is asked whether a network reaches it: its own API host, or, for a platform people host
 * themselves, the instance a credential names. Null when there is nowhere to ask.
 */
export function originFor(provider: ProviderId, token: string | null): string | null {
  const host = PROVIDER_INFO[provider].checkHost;
  if (host) return `https://${host}`;
  return token == null ? null : (PROVIDER[provider].instanceOf?.(token) ?? null);
}

/** One place per platform to ask, and one per instance the connected accounts of a self-hosted platform are on. */
export function testTargets(repo: Repo, vault: TokenVault): NetworkTarget[] {
  const accounts = repo.accounts.list();
  return PROVIDERS.flatMap((provider) => {
    if (PROVIDER_INFO[provider].checkHost) return [{ provider, origin: originFor(provider, null)! }];
    const tokens = new Set(accounts.filter((a) => a.provider === provider).map((a) => vault.get(a.tokenId)?.token ?? null));
    const origins = new Set([...tokens].map((t) => originFor(provider, t)).filter((o): o is string => !!o));
    return [...origins].sort().map((origin) => ({ provider, origin }));
  });
}

export interface NetworkTarget {
  provider: ProviderId;
  /** "https://api.github.com", or a self-hosted instance's own address. */
  origin: string;
}

/**
 * Before a scan through a network: is the network itself working? Asks the platform one thing, without a credential,
 * and throws when the network is what failed (its proxy is down or refuses the sign-in, its certificate is missing),
 * so the scan stops at once and says what to fix, instead of every request failing one by one and a scan full of gaps.
 * Anything else is left to the scan, which knows what each failure means.
 */
export async function checkRoute(route: Route | null, origin: string | null): Promise<void> {
  if (!route || !origin) return;
  try {
    const res = await through(route, () => request(`${origin}/`, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(20_000) }));
    await res.body?.cancel().catch(() => {});
  } catch (e) {
    if (e instanceof NetworkError && e.broken) throw e;
  }
}

const TEST_MS = 10_000;
/** Cloudflare's own page that says which address a request came from, and whether it came through WARP. */
const TRACE = "https://www.cloudflare.com/cdn-cgi/trace";

const failure = (e: unknown): string =>
  e instanceof NetworkError ? e.message : (e as Error)?.name === "TimeoutError" ? `No answer within ${TEST_MS / 1000} seconds.` : "The connection failed.";

/**
 * Whether each platform answers through a route, and the address the internet sees requests come from. Sends one GET
 * per target with no credential: any answer, even "unauthorized", means the platform was reached.
 */
export async function testRoute(route: Route | null, targets: NetworkTarget[]): Promise<NetworkTestResponse> {
  return through(route, async () => {
    const reach = async ({ provider, origin }: NetworkTarget): Promise<NetworkReach> => {
      const host = new URL(origin).host;
      const started = Date.now();
      try {
        const res = await request(`${origin}/`, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(TEST_MS) });
        await res.body?.cancel().catch(() => {});
        return { provider, host, ok: true, ms: Date.now() - started, error: null };
      } catch (e) {
        return { provider, host, ok: false, ms: null, error: failure(e) };
      }
    };
    const egress = async (): Promise<NetworkTestResponse["egress"]> => {
      try {
        const res = await request(TRACE, { method: "GET", signal: AbortSignal.timeout(TEST_MS) });
        if (!res.ok) return null;
        const text = (await res.text()).slice(0, 4000);
        const address = /^ip=([0-9a-fA-F:.]{3,45})$/m.exec(text)?.[1];
        return address ? { address, warp: /^warp=(on|plus)$/m.test(text) } : null;
      } catch {
        return null;
      }
    };
    const [seen, ...reached] = await Promise.all([egress(), ...targets.map(reach)]);
    return { egress: seen, reached };
  });
}
